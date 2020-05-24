from django.db import models

# Create your models here.
class CRPModels(models.Model):
    device_id=models.CharField(max_length=64)
    challenge=models.CharField(max_length=1024,primary_key=True)
    response=models.CharField(max_length=257)
    used_times=models.CharField(max_length=100)
    update_time=models.CharField(max_length=100)
    identity = models.CharField(max_length=10)

    def __str__(self):
        return self.device_id
class CRPTModels(models.Model):
    device_id=models.CharField(max_length=64)
    challenge=models.CharField(max_length=1024)
    response=models.CharField(max_length=257)
    used_times=models.CharField(max_length=100)
    update_time=models.CharField(max_length=100)