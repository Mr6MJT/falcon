"""Celery application for the worker.

The worker is the ONLY service with (gateway-mediated) internet egress. It reuses the same
orchestrator functions as the inline runner — Celery only provides queues, retries, and
fan-out; the DB remains the source of truth for DAG state.
"""

from __future__ import annotations

import os

from celery import Celery

BROKER = os.environ.get("ORVEX_REDIS_URL", "redis://redis:6379/0")

celery_app = Celery("orvex", broker=BROKER, backend=BROKER)
celery_app.conf.update(
    task_default_queue="recon",
    task_routes={
        "orvex.stage.active": {"queue": "active"},
        "orvex.stage.findings": {"queue": "cpu"},
        "orvex.report.*": {"queue": "report"},
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=int(os.environ.get("ORVEX_SOFT_TIME_LIMIT", "3600")),
    task_time_limit=int(os.environ.get("ORVEX_TIME_LIMIT", "3900")),
)

# Register tasks.
from apps.worker import tasks  # noqa: F401
