
import health_check

from celery import Celery
from time import sleep

rbacHealthCheck = health_check.contrib.celery_ping.backends.CeleryPingHealthCheck()
print("I'm currently within healthcheck.py")

def delay():
    sleep (10)
    
def check_health():
    print("AHHHHHHHHHH")
    print("check_status", rbacHealthCheck.check_status())
    check_status = rbacHealthCheck.check_status()
    return check_status