from rest_framework import serializers
from .models import *

class CRPSerializer(serializers.ModelSerializer):
    class Meta:
        model = CRPModels
        fields = ('device_id','challenge','response','used_times','update_time','identity')

class CRPTSerializer(serializers.ModelSerializer):
    class Meta:
        model = CRPModels
        fields = ('device_id','challenge','response','used_times','update_time')

