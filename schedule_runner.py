"""
Tiny companion process that only refreshes the
`sales-today` cache once a minute.  It imports the same
Flask app so it re-uses your `cache` object and DB config.
"""

import time, signal, sys, logging
from app import app, refresh_sales_cache, cache      # ← import from your code
from apscheduler.schedulers.blocking import BlockingScheduler
from threading import Lock

# ------------------------------------------------------------------ logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("scheduler")

# ------------------------------------------------------------------ setup
sched      = BlockingScheduler(timezone="UTC")
fetch_lock = Lock()                     # in case you add more jobs later


@sched.scheduled_job("interval", minutes=1, id="sales_refresh", coalesce=True,
                     max_instances=1, next_run_time=None)   # run once right away
def scheduled_refresh():
    with fetch_lock, app.app_context():     # app context for cache & DB
        refresh_sales_cache()               # <- your existing helper
        log.info("✓ sales-today cache refreshed")

# ------------------------------------------------------------------ graceful exit
def _graceful(*_):
    log.info("Shutting down scheduler…")
    sched.shutdown(wait=False)
    sys.exit(0)

signal.signal(signal.SIGTERM, _graceful)
signal.signal(signal.SIGINT,  _graceful)

# ------------------------------------------------------------------ run
if __name__ == "__main__":
    log.info("Starting scheduler process")
    sched.start()          # blocks forever
