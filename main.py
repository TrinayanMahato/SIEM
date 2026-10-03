from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from services.alert_handlers import process_alert
from services.db import db
from services.firewall import block_ip, block_user_temporarily

app = FastAPI()

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/webhook")
async def receive_webhook(request: Request):
    """
    Endpoint to receive webhook alerts from Elastalert.
    """
    try:
        payload = await request.json()
        print("--- NEW ALERT RECEIVED FROM ELASTALERT ---")
        
        # 1. Immediately store the raw alert in the database
        alert_type = payload.get("rule_name", "unknown_alert")
        
        # Ensure payload is JSON serializable
        # payload is already a dict from JSON, so we can pass it directly to Json
        import json
        
        db_alert = await db.securityalert.create(
            data={
                "alert_type": alert_type,
                "raw_payload": json.dumps(payload)
            }
        )
        print(f"Stored new alert in DB with ID: {db_alert.id}")
        
        # Attach the ID so handlers can update the record with LLM reasoning later
        payload["_db_alert_id"] = db_alert.id
        
        # 2. Process the alert
        await process_alert(payload)
        
        return {"status": "success", "message": "Alert processed successfully", "alert_id": db_alert.id}
    except Exception as e:
        print(f"Error processing webhook: {e}")
        return {"status": "error", "message": "Failed to process alert payload"}


# ---------------------------------------------------------
# Human-in-the-Loop Action Endpoints
# (Called when the user clicks a button in the approval email)
# ---------------------------------------------------------

@app.get("/action/block-permanently", response_class=HTMLResponse)
async def action_block_permanently(alert_id: int, ip: str):
    """
    Triggered when the SOC analyst clicks 'Block Permanently' in the email.
    Applies a pfctl block on the IP.
    """
    print(f"[Action] Permanent block approved for IP: {ip} (Alert ID: {alert_id})")
    
    success = block_ip(ip)
    
    if success:
        return HTMLResponse(content=f"""
            <html><body style="font-family:Arial; text-align:center; padding:60px;">
                <h2 style="color:#c0392b;">🚫 IP {ip} has been permanently blocked.</h2>
                <p>Alert ID #{alert_id}.</p>
            </body></html>
        """, status_code=200)
    else:
        return HTMLResponse(content=f"""
            <html><body style="font-family:Arial; text-align:center; padding:60px;">
                <h2 style="color:#e67e22;">⚠️ Block command failed for IP {ip}.</h2>
                <p>pfctl failed. Please block manually.</p>
            </body></html>
        """, status_code=500)


@app.get("/action/no-action", response_class=HTMLResponse)
async def action_no_action(alert_id: int, ip: str):
    """
    Triggered when the SOC analyst clicks 'No Action' in the email.
    Dismisses the alert. No action is taken.
    """
    print(f"[Action] Alert #{alert_id} dismissed for IP: {ip}. No action taken.")
    
    return HTMLResponse(content=f"""
        <html><body style="font-family:Arial; text-align:center; padding:60px;">
            <h2 style="color:#27ae60;">✅ Alert dismissed for IP {ip}.</h2>
            <p>Alert ID #{alert_id}. No action was taken.</p>
        </body></html>
    """, status_code=200)


# ---------------------------------------------------------
# Physical-login multi-account attack: single decision endpoint
# ---------------------------------------------------------

@app.get("/action/users-decision", response_class=HTMLResponse)
async def action_users_decision(alert_id: int, users: str, decision: str):
    """
    Single endpoint for both email buttons.
      decision=yes -> lock every listed user for 1 hour (auto-unlock afterwards)
      decision=no  -> dismiss, no accounts locked
    `users` is a comma-separated list of usernames.
    """
    import asyncio
    import html as _html
    from services.firewall import PROTECTED_USERNAMES, block_user, _scheduled_user_unblock

    decision = decision.strip().lower()
    usernames = [u.strip() for u in users.split(",") if u.strip()]

    if decision == "no":
        print(f"[Action] Alert #{alert_id} dismissed for users: {usernames}. No action taken.")
        return HTMLResponse(content=f"""
            <html><body style="font-family:Arial; text-align:center; padding:60px;">
                <h2 style="color:#27ae60;">✅ Alert dismissed</h2>
                <p>Alert ID #{alert_id}. No accounts were locked ({_html.escape(', '.join(usernames))}).</p>
            </body></html>
        """, status_code=200)

    if decision != "yes":
        return HTMLResponse(content="<h3>Invalid decision. Use 'yes' or 'no'.</h3>", status_code=400)

    print(f"[Action] Multi-user block approved for {usernames} (Alert ID: {alert_id})")
    locked, failed = [], []
    for u in usernames:
        if u.lower() not in PROTECTED_USERNAMES and block_user(u):
            locked.append(u)
            asyncio.create_task(_scheduled_user_unblock(u, 3600))
        else:
            failed.append(u)

    locked_s = _html.escape(', '.join(locked) or 'none')
    failed_s = _html.escape(', '.join(failed) or 'none')
    return HTMLResponse(content=f"""
        <html><body style="font-family:Arial; text-align:center; padding:60px;">
            <h2 style="color:#c0392b;">🚫 Users locked for 1 hour</h2>
            <p><strong>Locked:</strong> {locked_s}</p>
            <p><strong>Skipped/failed (protected or command error):</strong> {failed_s}</p>
            <p>Alert ID #{alert_id}. Accounts will be re-enabled automatically.</p>
        </body></html>
    """, status_code=200 if locked else 500)


# ---------------------------------------------------------
# Privilege escalation: single yes/no decision endpoint
# ---------------------------------------------------------

@app.get("/action/ip-decision", response_class=HTMLResponse)
async def action_ip_decision(alert_id: int, ip: str, decision: str):
    """
    Single endpoint for both email buttons.
      decision=yes -> block the IP (and all its access) via pfctl
      decision=no  -> do nothing
    """
    import html as _html
    decision = decision.strip().lower()
    safe_ip = _html.escape(ip)

    if decision == "no":
        print(f"[Action] Alert #{alert_id} dismissed for IP {ip}. No action taken.")
        return HTMLResponse(content=f"""
            <html><body style="font-family:Arial; text-align:center; padding:60px;">
                <h2 style="color:#27ae60;">✅ Alert dismissed</h2>
                <p>Alert ID #{alert_id}. IP {safe_ip} was not blocked.</p>
            </body></html>
        """, status_code=200)

    if decision != "yes":
        return HTMLResponse(content="<h3>Invalid decision. Use 'yes' or 'no'.</h3>", status_code=400)

    print(f"[Action] IP block approved for {ip} (Alert ID: {alert_id})")
    if block_ip(ip):
        return HTMLResponse(content=f"""
            <html><body style="font-family:Arial; text-align:center; padding:60px;">
                <h2 style="color:#c0392b;">🚫 IP {safe_ip} has been blocked.</h2>
                <p>Alert ID #{alert_id}.</p>
            </body></html>
        """, status_code=200)
    return HTMLResponse(content=f"""
        <html><body style="font-family:Arial; text-align:center; padding:60px;">
            <h2 style="color:#e67e22;">⚠️ Block command failed for IP {safe_ip}.</h2>
            <p>pfctl failed. Please block manually.</p>
        </body></html>
    """, status_code=500)
