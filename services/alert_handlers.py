import json
from enum import Enum
from pydantic import BaseModel
from google.genai import types

from services.email_service import send_alert_email, send_permanent_block_approval_email, send_users_block_approval_email, send_ip_decision_email
from services.db import db
from services.whitelist import WHITELISTED_IPS
from services.firewall import block_ip_temporarily, block_user_temporarily
from services.es_client import es
from services.gemini_client import gemini_client
from services.queries import get_ssh_failed_logins_query, get_physical_login_failures_query, get_privilege_escalation_query, get_http_4xx_errors_query
from services.prompts import (
    SSH_FAILED_LOGINS_SYSTEM_PROMPT,
    get_ssh_user_prompt,
    PHYSICAL_LOGIN_SYSTEM_PROMPT,
    get_physical_login_user_prompt,
    PRIVILEGE_ESCALATION_SYSTEM_PROMPT,
    get_privilege_escalation_user_prompt,
    HTTP_4XX_ERRORS_SYSTEM_PROMPT,
    get_http_4xx_errors_user_prompt,
)


# ---------------------------------------------------------
# Structured Output Schema for Gemini
# ---------------------------------------------------------
class ActionEnum(str, Enum):
    normal = "normal"
    block_temporarily = "block_temporarily"
    block_permanently = "block_permanently"


class SSHAnalysisResult(BaseModel):
    action: ActionEnum
    reasoning: str


# ---------------------------------------------------------
# Elasticsearch Fetching Helper
# ---------------------------------------------------------
async def get_recent_ip_logs(ip_address: str) -> list:
    """Fetches recent logs from Elasticsearch for a given IP."""
    query = get_ssh_failed_logins_query(ip_address)
    try:
        response = await es.search(
            index="logstash-*",  # Update to match your actual index pattern
            body=query
        )
        hits = response["hits"]["hits"]
        return [hit["_source"] for hit in hits]
    except Exception as e:
        print(f"Failed to retrieve logs from Elasticsearch: {e}")
        return []


# ---------------------------------------------------------
# Individual Rule Handlers
# ---------------------------------------------------------
async def get_privilege_escalation_logs(host_name: str) -> tuple[list, dict]:
    """Fetches recent sudo logs + aggregations for a host from Elasticsearch."""
    query = get_privilege_escalation_query(host_name)
    try:
        response = await es.search(index="logstash-*", body=query)
        logs = [hit["_source"] for hit in response["hits"]["hits"]]
        return logs, response.get("aggregations", {})
    except Exception as e:
        print(f"Failed to retrieve privilege escalation logs from Elasticsearch: {e}")
        return [], {}


async def handle_privilege_escalation(payload: dict):
    print("Handling Privilege Escalation (sudo) Failure...")

    host_name = payload.get("host.name") or payload.get("host") or "unknown"
    if isinstance(host_name, dict):
        host_name = host_name.get("name", "unknown")

    if host_name == "unknown":
        print("Could not extract host.name from the alert payload.")
        # send_alert_email(payload)  # disabled (dry-run)
        return

    logs, aggs = await get_privilege_escalation_logs(host_name)
    user_prompt = get_privilege_escalation_user_prompt(host_name, logs, aggs)

    print("Analyzing privilege escalation logs with Gemini...")
    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=PRIVILEGE_ESCALATION_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=SSHAnalysisResult,
                temperature=0.1
            ),
        )
        analysis_dict = json.loads(response.text)
        print(f"Gemini Analysis for host {host_name}: {analysis_dict}")

        # Determine the IP to act on: payload first, else top source IP from ES
        target_ip = payload.get("source.ip") or payload.get("ip")
        if isinstance(target_ip, list):
            target_ip = target_ip[0] if target_ip else None
        if not target_ip:
            buckets = aggs.get("source_ips", {}).get("buckets", [])
            target_ip = buckets[0]["key"] if buckets else None

        # --- VIP Whitelist Check ---
        if analysis_dict["action"] != "normal" and target_ip in WHITELISTED_IPS:
            owner = WHITELISTED_IPS[target_ip]
            print(f"⚠️ SYSTEM OVERRIDE: IP {target_ip} is whitelisted ({owner}). Preventing block.")
            analysis_dict["action"] = "normal"
            analysis_dict["reasoning"] += f"\n\n[SYSTEM OVERRIDE]: Block prevented, IP belongs to whitelisted entity: {owner}."

        payload["gemini_analysis"] = analysis_dict

        db_alert_id = payload.get("_db_alert_id")
        if db_alert_id:
            await db.securityalert.update(
                where={"id": db_alert_id},
                data={
                    "logs_analyzed": len(logs),
                    "llm_verdict": analysis_dict["action"],
                    "llm_reasoning": analysis_dict["reasoning"]
                }
            )

        action = analysis_dict["action"]
        print(f"[Handler] Privilege escalation verdict for {host_name}: {action} (IP: {target_ip})")

        print(f"[DRY-RUN] LLM Action   : {action}")
        print(f"[DRY-RUN] LLM Reasoning: {analysis_dict['reasoning']}")

        # --- ENFORCEMENT DISABLED (dry-run) ---
        # if action in ("block_temporarily", "block_permanently") and not target_ip:
        #     print("[Handler] No IP found; cannot enforce a block. Alert email only.")
        # elif action == "block_temporarily":
        #     print(f"[Handler] Blocking {target_ip} for 1 hour...")
        #     await block_ip_temporarily(target_ip, 3600)
        # elif action == "block_permanently":
        #     print(f"[Handler] ⚠️ Sending approval email for permanent block of {target_ip}...")
        #     send_ip_decision_email(
        #         ip_address=target_ip,
        #         host_name=host_name,
        #         alert_id=payload.get("_db_alert_id", 0),
        #         reasoning=analysis_dict["reasoning"]
        #     )

    except Exception as e:
        print(f"Failed to analyze privilege escalation with Gemini: {e}")

    # send_alert_email(payload)


async def get_physical_login_logs(host_name: str) -> tuple[list, dict]:
    """Fetches recent auth logs + aggregations for a host from Elasticsearch."""
    query = get_physical_login_failures_query(host_name)
    try:
        response = await es.search(index="logstash-*", body=query)
        logs = [hit["_source"] for hit in response["hits"]["hits"]]
        aggs = response.get("aggregations", {})
        return logs, aggs
    except Exception as e:
        print(f"Failed to retrieve physical login logs from Elasticsearch: {e}")
        return [], {}


async def handle_physical_login(payload: dict):
    print("Handling Physical Console Login Failure...")

    host_name = payload.get("host.name") or payload.get("host") or "unknown"
    if isinstance(host_name, dict):
        host_name = host_name.get("name", "unknown")

    if host_name == "unknown":
        print("Could not extract host.name from the alert payload.")
        # send_alert_email(payload)  # disabled (dry-run)
        return

    logs, aggs = await get_physical_login_logs(host_name)
    user_prompt = get_physical_login_user_prompt(host_name, logs, aggs)

    print("Analyzing physical login logs with Gemini...")
    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=PHYSICAL_LOGIN_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=SSHAnalysisResult,
                temperature=0.1
            ),
        )
        analysis_dict = json.loads(response.text)
        print(f"Gemini Analysis for host {host_name}: {analysis_dict}")

        payload["gemini_analysis"] = analysis_dict

        db_alert_id = payload.get("_db_alert_id")
        if db_alert_id:
            await db.securityalert.update(
                where={"id": db_alert_id},
                data={
                    "logs_analyzed": len(logs),
                    "llm_verdict": analysis_dict["action"],
                    "llm_reasoning": analysis_dict["reasoning"]
                }
            )
            print(f"Updated DB Alert ID {db_alert_id} with Gemini analysis.")

        # --- Enforce the verdict: lock the USERNAME for 1 hour (no IP blocking) ---
        username = payload.get("user.name") or payload.get("user")
        if isinstance(username, dict):
            username = username.get("name")
        if not username:
            # Fall back to the most-targeted user from the ES aggregation
            buckets = aggs.get("distinct_users", {}).get("buckets", [])
            username = buckets[0]["key"] if buckets else None

        action = analysis_dict["action"]
        print(f"[Handler] Physical login verdict for {host_name}: {action} (user: {username})")

        print(f"[DRY-RUN] LLM Action   : {action}")
        print(f"[DRY-RUN] LLM Reasoning: {analysis_dict['reasoning']}")

        # --- ENFORCEMENT DISABLED (dry-run) ---
        # if action == "block_temporarily":
        #     if not username:
        #         print("[Handler] No username found; cannot lock account. Alert email only.")
        #     else:
        #         print(f"[Handler] Locking user '{username}' for 1 hour...")
        #         await block_user_temporarily(username, 3600)
        # elif action == "block_permanently":
        #     # Many accounts under attack: ask a human before locking ALL of them
        #     buckets = aggs.get("distinct_users", {}).get("buckets", [])
        #     all_users = [b["key"] for b in buckets] or ([username] if username else [])
        #     if not all_users:
        #         print("[Handler] No usernames found; cannot request approval. Alert email only.")
        #     else:
        #         print(f"[Handler] ⚠️ Multi-account attack on {host_name}. Sending approval email for users: {all_users}")
        #         send_users_block_approval_email(
        #             usernames=all_users,
        #             host_name=host_name,
        #             alert_id=payload.get("_db_alert_id", 0),
        #             reasoning=analysis_dict["reasoning"]
        #         )

    except Exception as e:
        print(f"Failed to analyze physical login with Gemini: {e}")

    # send_alert_email(payload)


async def handle_multiple_failed_login_attempts(payload: dict):
    print("Executing specific logic for Multiple Failed Login Attempts.")
    
    # Convert payload to a string to easily search for the process path, 
    # since Elastalert payloads can sometimes nest fields deeply.
    import json
    payload_str = json.dumps(payload).lower()
    
    if "sudo" in payload_str:
        await handle_privilege_escalation(payload)
    elif "login" in payload_str:
        await handle_physical_login(payload)
    else:
        print("Could not determine specific login type. Falling back to default handling.")
        # send_alert_email(payload)  # disabled (dry-run)


def _extract_status_code(payload: dict) -> str:
    """Pulls the HTTP status code out of an Elastalert payload (flat or nested)."""
    code = (
        payload.get("http.response.status_code")
        or payload.get("status_code")
        or payload.get("status")
        or payload.get("response")
    )
    if code is None:
        code = payload.get("http", {}).get("response", {}).get("status_code") if isinstance(payload.get("http"), dict) else None
    if isinstance(code, list):
        code = code[0] if code else None
    return str(code).strip() if code is not None else ""


async def get_http_4xx_logs(ip_address: str) -> tuple[list, dict]:
    """Fetches recent 4xx web logs + aggregations for an IP from Elasticsearch."""
    query = get_http_4xx_errors_query(ip_address)
    try:
        response = await es.search(index="logstash-*", body=query)
        logs = [hit["_source"] for hit in response["hits"]["hits"]]
        return logs, response.get("aggregations", {})
    except Exception as e:
        print(f"Failed to retrieve HTTP 4xx logs from Elasticsearch: {e}")
        return [], {}


async def handle_http_error_spike(payload: dict):
    print("Executing specific logic for HTTP Error Spike.")

    # --- Only 4xx (client-side) errors are analyzed ---
    status_code = _extract_status_code(payload)
    if not (len(status_code) == 3 and status_code.startswith("4")):
        print(f"[Handler] Status code '{status_code}' is not 4xx. Skipping AI analysis.")
        # send_alert_email(payload)  # disabled (dry-run)
        return

    ip_address = payload.get("source.ip") or payload.get("ip") or payload.get("client.ip")
    if isinstance(ip_address, list):
        ip_address = ip_address[0] if ip_address else None
    if not ip_address:
        print("Could not extract an IP address from the alert payload.")
        # send_alert_email(payload)  # disabled (dry-run)
        return

    print(f"Querying Elasticsearch for recent 4xx logs from IP: {ip_address}")
    logs, aggs = await get_http_4xx_logs(ip_address)
    user_prompt = get_http_4xx_errors_user_prompt(ip_address, logs, aggs)

    print("Analyzing HTTP 4xx logs with Gemini...")
    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=HTTP_4XX_ERRORS_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=SSHAnalysisResult,
                temperature=0.1
            ),
        )
        analysis_dict = json.loads(response.text)
        print(f"Gemini Analysis for {ip_address}: {analysis_dict}")

        # --- VIP Whitelist Check ---
        if analysis_dict["action"] != "normal" and ip_address in WHITELISTED_IPS:
            owner = WHITELISTED_IPS[ip_address]
            print(f"⚠️ SYSTEM OVERRIDE: IP {ip_address} is whitelisted ({owner}). Preventing block.")
            analysis_dict["action"] = "normal"
            analysis_dict["reasoning"] += f"\n\n[SYSTEM OVERRIDE]: Block prevented, IP belongs to whitelisted entity: {owner}."

        payload["gemini_analysis"] = analysis_dict

        db_alert_id = payload.get("_db_alert_id")
        if db_alert_id:
            await db.securityalert.update(
                where={"id": db_alert_id},
                data={
                    "logs_analyzed": len(logs),
                    "llm_verdict": analysis_dict["action"],
                    "llm_reasoning": analysis_dict["reasoning"]
                }
            )

        action = analysis_dict["action"]
        print(f"[Handler] HTTP 4xx verdict for {ip_address}: {action}")

        print(f"[DRY-RUN] LLM Action   : {action}")
        print(f"[DRY-RUN] LLM Reasoning: {analysis_dict['reasoning']}")

        # --- ENFORCEMENT DISABLED (dry-run) ---
        # if action == "block_temporarily":
        #     print(f"[Handler] Blocking {ip_address} for 1 hour...")
        #     await block_ip_temporarily(ip_address, 3600)
        # elif action == "block_permanently":
        #     # Reuses the existing /action/ip-decision API (yes => block IP, no => nothing)
        #     print(f"[Handler] ⚠️ Sending approval email for permanent block of {ip_address}...")
        #     host_name = payload.get("host.name") or payload.get("host") or "web server"
        #     if isinstance(host_name, dict):
        #         host_name = host_name.get("name", "web server")
        #     send_ip_decision_email(
        #         ip_address=ip_address,
        #         host_name=host_name,
        #         alert_id=payload.get("_db_alert_id", 0),
        #         reasoning=analysis_dict["reasoning"],
        #         title="Web Scanning / Brute Force Attack",
        #         description=(
        #             f"A spike of <strong>HTTP 4xx</strong> errors was detected from IP "
        #             f"<code>{ip_address}</code> against <code>{host_name}</code>."
        #         ),
        #     )

    except Exception as e:
        print(f"Failed to analyze HTTP error spike with Gemini: {e}")

    # send_alert_email(payload)


async def handle_ssh_failed_logins(payload: dict):
    print("Executing specific logic for SSH Failed Logins.")

    ip_address = payload.get("source.ip", payload.get("ip", "unknown"))

    if ip_address != "unknown":
        print(f"Querying Elasticsearch for recent logs from IP: {ip_address}")
        logs = await get_recent_ip_logs(ip_address)

        user_prompt = get_ssh_user_prompt(ip_address, logs)

        print("Analyzing logs with Gemini...")
        try:
            response = gemini_client.models.generate_content(
                model="gemini-3.5-flash",
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SSH_FAILED_LOGINS_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=SSHAnalysisResult,
                    temperature=0.1
                ),
            )
            analysis = response.text
            print(f"Gemini Analysis for {ip_address}: {analysis}")
            
            analysis_dict = json.loads(analysis)
            
            # --- VIP Whitelist Check ---
            # If the AI suggests blocking, check if the IP is an executive or internal
            if analysis_dict["action"] in ["block_temporarily", "block_permanently"]:
                if ip_address in WHITELISTED_IPS:
                    owner = WHITELISTED_IPS[ip_address]
                    print(f"⚠️ SYSTEM OVERRIDE: IP {ip_address} is whitelisted ({owner}). Preventing block.")
                    
                    # Override the AI's decision to prevent the block
                    analysis_dict["action"] = "normal"
                    analysis_dict["reasoning"] += f"\n\n[SYSTEM OVERRIDE]: Automated block was prevented because the IP belongs to a whitelisted entity: {owner}."
            
            payload["gemini_analysis"] = analysis_dict
            
            db_alert_id = payload.get("_db_alert_id")
            if db_alert_id:
                # Update the database record with LLM reasoning
                await db.securityalert.update(
                    where={"id": db_alert_id},
                    data={
                        "logs_analyzed": len(logs),
                        "llm_verdict": analysis_dict["action"],
                        "llm_reasoning": analysis_dict["reasoning"]
                    }
                )
                print(f"Updated DB Alert ID {db_alert_id} with Gemini analysis.")
            
            print(f"[DRY-RUN] LLM Action   : {analysis_dict['action']}")
            print(f"[DRY-RUN] LLM Reasoning: {analysis_dict['reasoning']}")

            # --- ENFORCEMENT DISABLED (dry-run) ---
            # if analysis_dict["action"] == "block_temporarily":
            #     print(f"[Handler] LLM recommended temporary block for {ip_address}. Enforcing...")
            #     await block_ip_temporarily(ip_address)
            # elif analysis_dict["action"] == "block_permanently":
            #     # Permanent block requires human approval — send an email with action buttons
            #     db_id = payload.get("_db_alert_id", 0)
            #     print(f"[Handler] ⚠️ LLM recommended PERMANENT block for {ip_address}. Sending approval email...")
            #     send_permanent_block_approval_email(
            #         ip_address=ip_address,
            #         alert_id=db_id,
            #         reasoning=analysis_dict["reasoning"]
            #     )

        except Exception as e:
            print(f"Failed to analyze with Gemini: {e}")
    else:
        print("Could not extract an IP address from the alert payload.")

    # send_alert_email(payload)


async def handle_unknown_rule(payload: dict):
    print("Executing fallback logic for unknown rule.")
    # send_alert_email(payload)  # disabled (dry-run)


# ---------------------------------------------------------
# Main Alert Router (Switch Case)
# ---------------------------------------------------------
async def process_alert(payload: dict):
    rule_name = payload.get("rule_name")
    print(f"Routing alert for rule: {rule_name}")

    if rule_name == "Multiple Failed Login Attempts":
        await handle_multiple_failed_login_attempts(payload)
    elif rule_name == "HTTP Error Spike":
        await handle_http_error_spike(payload)
    elif rule_name == "SSH Failed Logins":
        await handle_ssh_failed_logins(payload)
    else:
        await handle_unknown_rule(payload)
