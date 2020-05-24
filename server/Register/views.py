from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.forms.models import model_to_dict
from rest_framework.reverse import reverse
from .models import *
from .serializer import *
from rest_framework import mixins,generics,permissions
from rest_framework.generics import ListAPIView, RetrieveAPIView
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework import generics
from .models import *
from rest_framework import mixins
from rest_framework.viewsets import GenericViewSet,ViewSet
from rest_framework.decorators import action
from django.shortcuts import HttpResponse
from rest_framework import permissions
from rest_framework import generics
import json
from random import *
from kerberos_base_puf.Simplified_Arbiter_PUF import *
from kerberos_base_puf.ArbiterPUF import *
from kerberos_base_puf.CRP import *
from kerberos_base_puf.PUFAttackSimulation import *
import hashlib
import string
import requests
import os
import time
from .sm4 import *
def init_puf():
    f=open('./puf_seed.json','r+')
    seed=f.read()
    puf_seed=list(json.loads(seed))
    origin_puf=SimplifiedArbiterPUF(puf_seed)
    return origin_puf

def get_crp(original_puf,challenge_input):
    random_num = int(challenge_input, 16)
    vector = list('{:01024b}'.format(random_num))
    challenge = []
    for i in vector:
        if i == '1':
            challenge.append(1)
        else:
            challenge.append(-1)
    return CRP(challenge,original_puf.get_response(challenge))


class RegisterViewSet(mixins.ListModelMixin,mixins.RetrieveModelMixin,GenericViewSet):
    queryset = CRPModels.objects.all()
    serializer_class = CRPSerializer

    @action(methods=['get'],detail=False)
    def register(self,request):
        cliend_id= ''.join(random.sample(string.ascii_letters + string.digits, 16))
        id=open('./client_id.ini','w+')
        id.write(cliend_id)
        puf_seed=get_random_vector(1024)
        f=open('./puf_seed.json','w+')
        f.write(json.dumps(puf_seed))
        original_puf=init_puf()
        for i in range(15):
            challenge="".join([choice("0123456789ABCDEF") for i in range(256)])
            crp=get_crp(original_puf,challenge)
            response=str(crp.response)
            s256=hashlib.sha256()
            s256.update(response.encode())
            responses=s256.hexdigest()
            keyword={
                "device":cliend_id,
                "challenge":challenge,
                "response":responses,
                "identity":"server"
            }
            r=requests.post('http://127.0.0.1:8001/register/registerin/',keyword)
            print(r.json())
            time.sleep(2)
        return Response({})

    @action(methods=['post'],detail=False)
    def testpuf(self,request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # 所以这里是真实的ip
        else:
            ip = request.META.get('REMOTE_ADDR')  # 这里获得代理ip
        print(ip)
        device_id=request.data["device_id"]
        challenge=request.data["challenge"]
        response=request.data["response"]
        original_puf=init_puf()
        crp=get_crp(original_puf,challenge)
        s256=hashlib.sha256()
        s256.update(str(crp.response).encode())
        responses=s256.hexdigest()
        if responses==response:
            print(1)
        else:
            print(0)
        return Response({})

    @action(methods=['get'],detail=False)
    def gettgt(self,request):
        f=open('./client_id.ini','r+')
        device_id=f.read()
        req_data={
            "device_id":device_id
        }
        r=requests.post("http://127.0.0.1:8001/register/givetgt/",req_data)
        res_data=r.json()
        katotgsen=res_data["katotgs"]
        tgt_file=open("./tgt.cache","w+")
        tgt_file.write(res_data["tgt"])
        challenge=res_data["challenge"]
        original_puf=init_puf()
        crp=get_crp(original_puf,challenge)
        response=str(crp.response)
        s256=hashlib.sha256()
        s256.update(response.encode())
        ka=s256.hexdigest()[0:16]
        print(ka)
        s4=sm4kerberos()
        katotgs=s4.decrypt(ka,katotgsen)
        print(katotgs)
        f=open("./katotgs.key","w+")
        f.write(katotgs.decode('utf-8'))
        return Response(r.json())

    @action(methods=['post'],detail=False)
    def checksgt(self,request):
        challenge=request.data["challenge"]
        sgt=request.data["sgt"]
        auth  = request.data["auth"]


        original_puf=init_puf()
        crp=get_crp(original_puf,challenge)
        response = str(crp.response)
        s256=hashlib.sha256()
        s256.update(response.encode())
        kb=s256.hexdigest()[0:16]
        print(kb)
        sm4=sm4kerberos()
        sgt_detail=eval(sm4.decrypt(kb,sgt))
        katob = sgt_detail["katob"]
        authatob = eval(sm4.decrypt(katob,auth))
        print(sgt_detail)
        print(authatob)
        if authatob["device_id"] != sgt_detail["client_id"]:
            return Response({"checksgt":'failed'})
        else:
            return Response({"checksgt":'success'})