"""
core/api.py
===========
FastAPI backend server providing REST API and WebSocket endpoints
for the dashboard and CLI integration.
"""

import asyncio
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import uuid

from core.config import settings
from core.models import ScanResult, ScanStatus, Severity, VulnType
from loguru import logger


# ── Pydantic Request/Response Schemas ────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    modules: List[str] = ["recon", "crawl", "sqli", "xss", "cmdi", "idor", "auth"]
    depth: int = 3
    threads: int = 10
    auth_token: Optional[str] = None
    cookies: Dict[str, str] = {}
    extra_headers: Dict[str, str] = {}

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    progress: float
    started_at: Optional[str]
    vulnerabilities_found: int
    endpoints_found: int
    current_module: Optional[str]

class VulnerabilityResponse(BaseModel):
    vuln_id: str
    vuln_type: str
    severity: str
    title: str
    description: str
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    cvss_score: float
    confidence: float
    remediation: str
    discovered_at: str


# ── In-memory scan store (replace with DB in production) ─────────────────────

active_scans: Dict[str, Dict] = {}
scan_results: Dict[str, ScanResult] = {}


# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)

    async def broadcast(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Bug Bounty Scanner API",
    description="Production-grade autonomous vulnerability discovery system",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Scan Orchestrator ─────────────────────────────────────────────────────────

async def run_scan_pipeline(scan_id: str, request: ScanRequest):
    """
    Main scan pipeline orchestrator.
    Runs all modules in sequence and broadcasts progress via WebSocket.
    """
    from recon.engine import ReconEngine
    from crawler.engine import CrawlerEngine
    from scanner.sqli import SQLiScanner
    from scanner.xss import XSSScanner
    from scanner.cmdi import CMDiScanner
    from scanner.idor import IDORScanner
    from scanner.auth import AuthScanner
    from ai_engine.engine import AIEngine
    from risk_engine.scorer import RiskScorer
    from reporter.generator import ReportGenerator
    from core.session import ScanSession
    from core.models import ScanResult, ScanStatus
    from core.config import ScanConfig
    import time

    result = ScanResult(
        scan_id=scan_id,
        target=request.target,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow(),
    )
    scan_results[scan_id] = result
    active_scans[scan_id]["status"] = "running"

    config = ScanConfig(
        target=request.target,
        depth=request.depth,
        threads=request.threads,
        modules=request.modules,
        cookies=request.cookies,
        headers=request.extra_headers,
    )

    start_time = time.time()
    progress = 0.0

    async def broadcast_update(module: str, pct: float, message: str, data: dict = None):
        active_scans[scan_id]["progress"] = pct
        active_scans[scan_id]["current_module"] = module
        await manager.broadcast(scan_id, {
            "type": "progress",
            "scan_id": scan_id,
            "module": module,
            "progress": pct,
            "message": message,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat(),
        })

    try:
        async with ScanSession(
            rate_limit=config.threads,
            timeout=config.timeout,
            cookies=config.cookies,
            extra_headers=config.headers,
        ) as session:

            # ── Phase 1: Reconnaissance ───────────────────────────────────────
            if "recon" in config.modules:
                await broadcast_update("recon", 5, "Starting reconnaissance...")
                recon_engine = ReconEngine(session, config)
                result.recon = await recon_engine.run(request.target)
                active_scans[scan_id]["recon_complete"] = True
                await broadcast_update("recon", 20, "Reconnaissance complete",
                    {"subdomains": result.recon.subdomains[:5]})

            # ── Phase 2: Crawling ─────────────────────────────────────────────
            if "crawl" in config.modules:
                await broadcast_update("crawler", 25, "Crawling target...")
                crawler = CrawlerEngine(session, config)
                result.endpoints = await crawler.crawl(request.target)
                active_scans[scan_id]["endpoints_found"] = len(result.endpoints)
                await broadcast_update("crawler", 40, f"Discovered {len(result.endpoints)} endpoints",
                    {"endpoint_count": len(result.endpoints)})

            # ── Phase 3: AI Attack Planning ───────────────────────────────────
            await broadcast_update("ai_engine", 42, "AI planning attack vectors...")
            ai_engine = AIEngine()
            result.attack_vectors = await ai_engine.plan_attacks(result.endpoints, result.recon)
            await broadcast_update("ai_engine", 45, f"Identified {len(result.attack_vectors)} attack vectors")

            # ── Phase 4: Vulnerability Scanning ──────────────────────────────
            scanners = []
            if "sqli"      in config.modules: scanners.append(SQLiScanner(session, config))
            if "xss"       in config.modules: scanners.append(XSSScanner(session, config))
            if "cmdi"      in config.modules: scanners.append(CMDiScanner(session, config))
            if "idor"      in config.modules: scanners.append(IDORScanner(session, config))
            if "auth"      in config.modules: scanners.append(AuthScanner(session, config))

            total_scanners = len(scanners)
            for idx, scanner_module in enumerate(scanners):
                module_name = scanner_module.__class__.__name__
                pct = 45 + (idx / max(total_scanners, 1)) * 40
                await broadcast_update(module_name, pct, f"Running {module_name}...")

                vulns = await scanner_module.scan(result.endpoints, result.attack_vectors)
                result.vulnerabilities.extend(vulns)

                # Broadcast each new vulnerability
                for v in vulns:
                    await manager.broadcast(scan_id, {
                        "type": "vulnerability",
                        "scan_id": scan_id,
                        "vulnerability": {
                            "vuln_id": v.vuln_id,
                            "vuln_type": v.vuln_type.value,
                            "severity": v.severity.value,
                            "title": v.title,
                            "url": v.url,
                            "cvss_score": v.cvss_score,
                        },
                        "timestamp": datetime.utcnow().isoformat(),
                    })

                active_scans[scan_id]["vulnerabilities_found"] = len(result.vulnerabilities)

            # ── Phase 5: Risk Scoring ─────────────────────────────────────────
            await broadcast_update("risk_engine", 88, "Scoring vulnerabilities...")
            scorer = RiskScorer()
            result.vulnerabilities = scorer.score_all(result.vulnerabilities)

            # ── Phase 6: Report Generation ────────────────────────────────────
            await broadcast_update("reporter", 93, "Generating reports...")
            reporter = ReportGenerator()
            report_paths = await reporter.generate_all(result)
            active_scans[scan_id]["report_paths"] = report_paths

            # ── Finalize ──────────────────────────────────────────────────────
            result.status = ScanStatus.COMPLETED
            result.completed_at = datetime.utcnow()
            result.duration_seconds = time.time() - start_time
            result.stats = {
                "total_requests": session.request_count,
                "endpoints_discovered": len(result.endpoints),
                "vulnerabilities_found": len(result.vulnerabilities),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "duration": result.duration_seconds,
            }

            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["progress"] = 100

            await broadcast_update("complete", 100, "Scan completed successfully!", result.stats)
            logger.success(f"Scan {scan_id} completed — {len(result.vulnerabilities)} vulns found")

    except Exception as e:
        result.status = ScanStatus.FAILED
        result.error = str(e)
        active_scans[scan_id]["status"] = "failed"
        logger.error(f"Scan {scan_id} failed: {e}")
        await manager.broadcast(scan_id, {
            "type": "error",
            "scan_id": scan_id,
            "message": str(e),
        })


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html><body style="font-family:monospace;background:#0a0e1a;color:#00e5ff;padding:40px">
    <h1>🔍 AI Bug Bounty Scanner API</h1>
    <p>Visit <a href="/api/docs" style="color:#00ff9d">/api/docs</a> for interactive documentation</p>
    </body></html>
    """

@app.post("/api/scans", response_model=dict, status_code=201)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new vulnerability scan."""
    # Ethics check
    if not request.target or len(request.target) < 3:
        raise HTTPException(400, "Invalid target domain")

    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "status": "pending",
        "progress": 0,
        "started_at": datetime.utcnow().isoformat(),
        "vulnerabilities_found": 0,
        "endpoints_found": 0,
        "current_module": None,
    }

    background_tasks.add_task(run_scan_pipeline, scan_id, request)
    logger.info(f"Scan {scan_id} queued for target: {request.target}")

    return {"scan_id": scan_id, "status": "pending", "message": "Scan started"}


@app.get("/api/scans", response_model=List[dict])
async def list_scans():
    """List all scans."""
    return list(active_scans.values())


@app.get("/api/scans/{scan_id}", response_model=dict)
async def get_scan(scan_id: str):
    """Get scan status and basic info."""
    if scan_id not in active_scans:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return active_scans[scan_id]


@app.get("/api/scans/{scan_id}/vulnerabilities", response_model=List[dict])
async def get_vulnerabilities(scan_id: str, severity: Optional[str] = None):
    """Get vulnerabilities for a scan."""
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan results not found")
    
    vulns = scan_results[scan_id].vulnerabilities
    if severity:
        vulns = [v for v in vulns if v.severity.value == severity.lower()]
    
    return [
        {
            "vuln_id": v.vuln_id,
            "vuln_type": v.vuln_type.value,
            "severity": v.severity.value,
            "title": v.title,
            "description": v.description,
            "url": v.url,
            "parameter": v.parameter,
            "payload": v.payload,
            "cvss_score": v.cvss_score,
            "confidence": v.confidence,
            "remediation": v.remediation,
            "discovered_at": v.discovered_at.isoformat(),
        }
        for v in vulns
    ]


@app.get("/api/scans/{scan_id}/endpoints", response_model=List[dict])
async def get_endpoints(scan_id: str):
    """Get discovered endpoints for a scan."""
    if scan_id not in scan_results:
        raise HTTPException(404, "Scan results not found")
    return [
        {
            "url": e.url,
            "method": e.method.value,
            "status_code": e.status_code,
            "is_api": e.is_api,
            "params": list(e.params.keys()),
        }
        for e in scan_results[scan_id].endpoints
    ]


@app.get("/api/scans/{scan_id}/report")
async def download_report(scan_id: str, format: str = "html"):
    """Download scan report."""
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
    report_paths = active_scans[scan_id].get("report_paths", {})
    path = report_paths.get(format)
    if not path:
        raise HTTPException(404, f"Report in format '{format}' not yet available")
    return FileResponse(path)


@app.delete("/api/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
    active_scans[scan_id]["status"] = "cancelled"
    return {"message": "Scan cancellation requested"}


@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress."""
    await manager.connect(scan_id, websocket)
    try:
        # Send current state immediately on connect
        if scan_id in active_scans:
            await websocket.send_json({
                "type": "connected",
                "scan_id": scan_id,
                "current_state": active_scans[scan_id],
            })
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "active_scans": len([s for s in active_scans.values() if s["status"] == "running"]),
    }
