from health_check.backends import BaseHealthCheckbackend
from management.tasks import run_celery_beat_scheduler_in_worker

class MyHealthCheckBackend(BaseHealthCheckbackend):
    #The status endpoints will respond with a 200 status code
    #even if the check errors. 

    critical_service = False

    def check_status(self):
        #the test code goes here 
        # You can use self.add_error or raise a 'HealthCheckException'
        # similar to Django's form validation 
        print("hello world")
        

    def identifier(self): 
        return self.__class__.__name__


