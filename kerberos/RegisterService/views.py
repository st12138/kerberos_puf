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
import hashlib
import random
import datetime
import time
from .sm4 import *

new_register = "you need register again"
limitnum = 5
class RegisterInViewSet(mixins.ListModelMixin,mixins.RetrieveModelMixin,GenericViewSet):
    queryset = CRPModels.objects.all()
    serializer_class = CRPSerializer

    @action(methods=['post'],detail=False)
    def registerin(self,request):
        device_id=request.data["device"]
        challenge=request.data["challenge"]
        response=request.data["response"]
        identity=request.data["identity"]
        time=datetime.datetime
        used_times=0
        print(identity)
        crp={
            "device_id":str(device_id),
            "challenge":challenge,
            "response":response,
            "used_times":str(used_times),
            "update_time":time.now().strftime('%Y-%m-%d %H:%M:%S')[0:19],
            "identity":str(identity)
        }
        print(crp)
        """
        id_hash=hashlib.sha256()
        id_hash.update(device_id)
        """
        ser = self.get_serializer(data=crp)
        if ser.is_valid():
            ser.save()
        return Response(self.get_queryset().values())

    @action(methods=['get'],detail=False)
    def checkcrp(self,request):
        return Response(self.get_queryset().values())


    @action(methods=['post'],detail=False)
    def givetgt(self,request):
        ktgs="thisistgskeyaaaa"
        device_id=request.data["device_id"]

        """
        request.session['username'] = device_id
        request.session['is_life'] = True
        request.session.set_expiry(10000)
        #print(request.session.get('username'))
        """

        obj=self.get_queryset().filter(device_id=device_id).values()
        print(obj.count())

        if obj.count() == 0:
            error = json.loads(new_register)
            return Response(error)
        num=random.randrange(0,obj.count())
        print(num)
        crp=obj[num]
        print(crp)
        #print(int(crp["used_times"]))
        """
        while int(crp["used_times"]) > limitnum:
            ser = self.get_serializer(data=crp)
            ser.delet()
            num = random.randrange(0, obj.count())
            print(num)
            crp = obj[num]
        crp["used_times"]= int(crp["used_times"])+1
        crp["update_time"] = time.now().strftime('%Y-%m-%d %H:%M:%S')[0:19]
        """
        ka=crp["response"][0:16]
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # 所以这里是真实的ip
        else:
            ip = request.META.get('REMOTE_ADDR')  # 这里获得代理ip
        print(ip)
        tgs_name="tgs"
        time_stamp=time.time()
        lifetime=600
        katotgs="".join([choice("0123456789ABCDEF") for i in range(16)])
        tatotgs={
            "device_id":device_id,
            "device_address":ip,
            "tgs_name":tgs_name,
            "time_stamp":time_stamp,
            "lifetime":lifetime,
            "katotgs":katotgs
        }
        print(time_stamp)
        s4=sm4kerberos()
        print(s4.encrypt(ktgs,str(tatotgs)))
        ret_data={
            "challenge":crp["challenge"],
            "tgt":s4.encrypt(ktgs,str(tatotgs)),
            "katotgs":s4.encrypt(ka,katotgs)
        }
        print(ret_data)
        f=open("./katotgs.key","w+")
        f.write(katotgs)
        return Response(ret_data)

    @action(methods=['post'], detail=False)
    def gettgt(self, request):
        nowtime = time.time()
        ktgs = "thisistgskeyaaaa"
        tgt = request.data["tgt"]
        auth = request.data["auth"]
        #server_id = request.data["server_id"]

        f = open("./katotgs.key", "r+")
        katotgs = f.read()
        sm4 = sm4kerberos()
        authatotgs = eval(sm4.decrypt(katotgs, auth))
        tgt_detail = eval(sm4.decrypt(ktgs, tgt))

        print(("tgtdetail: %s") % (tgt_detail))
        print(authatotgs)
        timediff = nowtime - tgt_detail['time_stamp']
        print("timediff:%d" % (timediff))
        if authatotgs["device_id"] != tgt_detail["device_id"] or timediff > tgt_detail['lifetime']:
            return Response({"wrong": "time out"})
        f = open('statue/'+authatotgs["device_id"]+'.cache','w+')
        t = hashlib.sha256(str(nowtime).encode()).hexdigest()
        f.write(t+":"+str(tgt_detail['time_stamp']))
        f.close()
        return Response({'token':t})

    @action(methods=['post'],detail=False)
    def givesgt(self,request):

        f = open("./katotgs.key", "r+")
        katotgs = f.read()
        f.close()
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # 所以这里是真实的ip
        else:
            ip = request.META.get('REMOTE_ADDR')  # 这里获得代理ip
        token=request.data["token"]
        server_id = request.data["server_id"]
        device_id = request.data["device_id"]
        try:
            f = open('statue/'+device_id+'.cache','r')
        except IOError:
            return Response({'wrong':'need tgt'})

        tt=f.read()
        print(token)
        print("tt:"+tt[:64])
        if token!=tt[:64]:
            return Response({'wrong': 'wrong token'})

        tgttime = float(tt[65:])
        nowtime = time.time()
        timediff = nowtime-tgttime
        if timediff>600:
            return Response({'wrong': 'time out'})
        server_info=self.get_queryset().filter(device_id=server_id).values()
    
        num = random.randrange(0, server_info.count())
        kb_crp=server_info[num]

        katob = "".join([choice("0123456789ABCDEF") for i in range(16)])
        print(kb_crp)
        print(katob)
        challenge_server=kb_crp["challenge"]
        kb=kb_crp["response"][0:16]
        tatob_detail={
            "client_id":device_id,
            "client_ip":ip,
            "server_id":server_id,
            "time_stamp":time.time(),
            "lifetime":600,
            "katob":katob
        }
        sm4=sm4kerberos()
        sgt=sm4.encrypt(kb,str(tatob_detail))
        print(kb)
        print(sgt)
        katobencrypt=sm4.encrypt(katotgs,katob)
        ret_data={
            "challenge":challenge_server,
            "sgt":sgt,
            "katob":katobencrypt
        }
        return Response(ret_data)

