from fastapi import APIRouter, HTTPException, Response

from backend.app.storage.records import export_audit_markdown, list_audits, load_audit

router = APIRouter()


@router.get("")
@router.get("/")
def list_audit_records(limit: int = 30) -> dict:
    return list_audits(limit)


@router.get("/{audit_id}")
def get_audit(audit_id: str) -> dict:
    audit = load_audit(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return audit


@router.get("/{audit_id}/export")
def export_audit(audit_id: str) -> Response:
    markdown = export_audit_markdown(audit_id)
    if markdown is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{audit_id}.md"'},
    )
