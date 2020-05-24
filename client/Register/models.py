from django.db import models

# Create your models here.
class CRPModels(models.Model):
    device_id=models.CharField(max_length=32,primary_key=True)
    challenge=models.CharField(max_length=1024)
    response=models.CharField(max_length=257)
    used_times=models.IntegerField()
