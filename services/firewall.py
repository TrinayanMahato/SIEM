import asyncio
import subprocess

BLOCK_DURATION_SECONDS = 3600 
PFCTL_TABLE = "siem_blocked"

# Accounts that must never be locked automatically.
PROTECTED_USERNAMES = {"root", "daemon", "nobody", "admin"}


def _run_pfctl(args: list[str]) -> bool:
    """
    Helper to execute a pfctl command with sudo.
    Returns True on success, False on failure.
    """
    try:
        result = subprocess.run(
            ["sudo", "pfctl"] + args,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print(f"[Firewall] pfctl command failed: {result.stderr.strip()}")
            return False
        return True
    except FileNotFoundError:
        print("[Firewall] ERROR: 'pfctl' not found. Is this a macOS system?")
        return False
    except subprocess.TimeoutExpired:
        print("[Firewall] ERROR: pfctl command timed out.")
        return False
    except Exception as e:
        print(f"[Firewall] Unexpected error running pfctl: {e}")
        return False


def block_ip(ip_address: str) -> bool:
    """
    Adds an IP to the <siem_blocked> pf table — effectively blocking it.
    Equivalent to: sudo pfctl -t siem_blocked -T add <ip>
    """
    print(f"[Firewall] Blocking IP: {ip_address}")
    success = _run_pfctl(["-t", PFCTL_TABLE, "-T", "add", ip_address])
    if success:
        print(f"[Firewall] ✅ IP {ip_address} has been blocked via pfctl.")
    return success


def unblock_ip(ip_address: str) -> bool:
    """
    Removes an IP from the <siem_blocked> pf table — restoring access.
    Equivalent to: sudo pfctl -t siem_blocked -T delete <ip>
    """
    print(f"[Firewall] Unblocking IP: {ip_address}")
    success = _run_pfctl(["-t", PFCTL_TABLE, "-T", "delete", ip_address])
    if success:
        print(f"[Firewall] ✅ IP {ip_address} has been unblocked.")
    return success


async def block_ip_temporarily(ip_address: str, duration_seconds: int = BLOCK_DURATION_SECONDS):
    """
    Blocks an IP immediately, then schedules an automatic unblock
    after `duration_seconds` in the background.
    The API response is NOT delayed — the unblock runs in the background.
    """
    blocked = block_ip(ip_address)

    if blocked:
        minutes = duration_seconds // 60
        print(f"[Firewall] IP {ip_address} will be auto-unblocked in {minutes} minute(s).")
        asyncio.create_task(_scheduled_unblock(ip_address, duration_seconds))


async def _scheduled_unblock(ip_address: str, delay_seconds: int):
    """
    Background coroutine: waits for the delay, then removes the block.
    """
    await asyncio.sleep(delay_seconds)
    print(f"[Firewall] ⏰ Auto-unblock timer expired for IP: {ip_address}")
    unblock_ip(ip_address)


# ---------------------------------------------------------
# macOS user account locking (for physical login failures)
# ---------------------------------------------------------
def _run_pwpolicy(username: str, flag: str) -> bool:
    """Runs: sudo pwpolicy -u <username> <flag>  (-disableuser / -enableuser)."""
    try:
        result = subprocess.run(
            ["sudo", "pwpolicy", "-u", username, flag],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print(f"[UserLock] pwpolicy {flag} failed for '{username}': {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        print(f"[UserLock] Unexpected error running pwpolicy: {e}")
        return False


def block_user(username: str) -> bool:
    """Disables a macOS user account so it cannot log in."""
    if username.lower() in PROTECTED_USERNAMES:
        print(f"[UserLock] Refusing to lock protected account '{username}'.")
        return False
    print(f"[UserLock] Locking user account: {username}")
    ok = _run_pwpolicy(username, "-disableuser")
    if ok:
        print(f"[UserLock] ✅ User '{username}' has been disabled.")
    return ok


def unblock_user(username: str) -> bool:
    """Re-enables a previously disabled macOS user account."""
    print(f"[UserLock] Unlocking user account: {username}")
    ok = _run_pwpolicy(username, "-enableuser")
    if ok:
        print(f"[UserLock] ✅ User '{username}' has been re-enabled.")
    return ok


async def block_user_temporarily(username: str, duration_seconds: int = BLOCK_DURATION_SECONDS):
    """Locks a user now and re-enables the account after `duration_seconds`."""
    if block_user(username):
        print(f"[UserLock] '{username}' will be auto-unlocked in {duration_seconds // 60} minute(s).")
        asyncio.create_task(_scheduled_user_unblock(username, duration_seconds))


async def _scheduled_user_unblock(username: str, delay_seconds: int):
    await asyncio.sleep(delay_seconds)
    print(f"[UserLock] ⏰ Auto-unlock timer expired for user: {username}")
    unblock_user(username)
