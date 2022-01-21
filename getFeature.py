#coding=utf8
import sys
import math
import os
import jieba
import subprocess
import re
from textrank4zh import TextRank4Keyword, TextRank4Sentence
import numpy as np

class GetFeature:
	def getIC(self,fullpath):     #计算重合指数
		cipher_file = open(fullpath,'r')
        	cipher = cipher_file.read()
        	letter = "abcdefghijklmnopqrstuvwxyz"
        	sum = 0.0
        	data = []
        	for i in letter:
            		for j in cipher:
               			if i == j:
                    			sum += 1
            		data.append(sum)
            		sum = 0.0

        	sum = 0.0
       		for i in data:	
            		sum += i

        	n = sum * (sum - 1)
        	sum = 0.0
        	for i in data:
           		if i != 0:
                		sum += i * (i - 1)
        	if n != 0:
            		IC = sum / n
            		#print("IC = ", IC)

            		if IC >= 0.040 and IC <= 0.055:
                		#print("Index of Coincidence =", IC)
				return IC
            		elif IC >= 0.01 and IC < 0.040:
                		#print("Index of Coincidence =", IC)
				return IC
            		elif IC > 0.055 and IC < 1:
                		#print("Index of Coincidence =", IC)
				return IC
           		else:
                		print("Can't Define The Cipher")
				return 0
        	else:
            		print("Can't Define The Cipher")
			return 0
    		#cipher_file.close()

	def getKeywords(self,fullpath):     #计算恶意特征函数出现次数
		file = open(fullpath, 'r')
    		txt = file.read()
    		words = jieba.lcut(txt)  
    		count1 = {}
    		num1 = 0
    		count2 = {}
    		num2 = 0
    		count3 = {}
    		num3 = 0
    		count4 = {}
    		num4 = 0
    		for word in words:  
        		if len(word) < 2:  
            			continue
        		else:
            			count1[word] = count1.get(word, 0) + 1  
            			count2[word] = count2.get(word, 0) + 1 
            			count3[word] = count3.get(word, 0) + 1 
            			count4[word] = count4.get(word, 0) + 1 
    		include1 = ['assert', 'eval', 'python_eval', 'shell', 'array_map', 'call_user_func', 'system', 'preg_replace', 'passthru', 'shell_exec', 'exec', 'proc_open', 'popen', 'curl_exec', 'curl_multi_exec', 'parse_ini_file', 'show_source']
    		include2 = ['file_get_contents', 'is_file', 'fopen', 'fclose', 'fwrite', 'wget', 'lynx', 'curl', 'posix_getpwuid', 'posix_getgrgid', 'fileowner', 'filegroup']
    		include3 = ['mysql_connect', 'mysql_query', 'mysql_num_fields', 'mysql_close', 'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_num_rows', 'mysql_result', 'mysql_affected_rows', 'mysql_select_db', 'mssql_connect', 'mssql _query', 'mssql_num_fields', 'mssql_field_name', 'mssql_fetch_array', 'mysql_close']
    		include4 = ['gzdeflat', 'gzcompress', 'gzuncompress', 'gzdecode', 'str_rot13', 'gzencode', 'base64_decode', 'base64_encode']   
	    	for key in list(count1.keys()):
			if key not in include1:
		    		del count1[key] 
	    		file.close()
	   	for key1 in count1.keys():
			num1 = num1 + count1[key1]
	    	for key in list(count2.keys()):  
			if key not in include2:
		    		del count2[key]  
	    		file.close()
	    	for key2 in count2.keys():
			num2 = num2 + count2[key2]
	    	for key in list(count3.keys()):  
			if key not in include3:
		    		del count3[key]  
	    		file.close()
	    	for key3 in count3.keys():
			num3 = num3 + count3[key3]
	    	for key in list(count4.keys()): 
			if key not in include4:
		    		del count4[key]  
	    		file.close()
	    	for key4 in count4.keys():
			num4 = num4 + count4[key4]
		#file.close()
		return num1,num2,num3,num4


   		
	def recursion_trans_php_file_opcode(self,fullpath):     #从php文件提取opcode
		#print("开始生成{}路径中的PHP的opcode操作码文件".format(fullpath))
		(filename_name, extension) = os.path.splitext(fullpath)
		if extension=='.php':	
			#print(filename_name)
			output = str(subprocess.check_output(
			["php", "-dvld.active=1","-dvld.execute=0",fullpath],stderr=subprocess.STDOUT))
			tokens = re.findall(r'\s(\b[A-Z_]+\b)\s', output)  #opcode操作符提取正则
			t = " ".join(tokens)
			return t.replace('E O E ', '')  #由于opcode正则会匹配每个func开头的非opcode字符，在这里去除
			#file_content = load_php_opcode(fullpath)
				
	def textrank_all(self,opcodes):     #计算opcode的TextRank值
		list_of_opcodes_dic = {
        'return': 0, 'init': 0, 'assign': 0, 'fetch': 0, 'fcall': 0, 'recv': 0, 'send': 0, 'call': 0, 'var': 0,
        'obj': 0,
        'val': 0, 'add': 0, 'jmpz': 0, 'method': 0, 'data': 0, 'concat': 0, 'icall': 0, 'dim': 0, 'jmp': 0, 'jmpnz': 0,
        'op': 0, 'static': 0, 'ref': 0, 'bool': 0, 'array': 0, 'identical': 0, 'smaller': 0, 'free': 0, 'bind': 0,
        'fe': 0,
        'cast': 0, 'equal': 0, 'isempty': 0, 'qm': 0, 'isset': 0, 'element': 0, 'class': 0, 'constant': 0, 'echo': 0,
        'reset': 0,
        'cv': 0, 'type': 0, 'global': 0, 'prop': 0, 'unset': 0, 'post': 0, 'nop': 0, 'check': 0, 'case': 0, 'count': 0,
        'rope': 0, 'eval': 0, 'arg': 0, 'silence': 0, 'mul': 0, 'bw': 0, 'strlen': 0, 'func': 0, 'exit': 0, 'ns': 0,
        'include': 0, 'switch': 0, 'pre': 0, 'throw': 0, 'rw': 0, 'string': 0, 'declare': 0, 'list': 0, 'defined': 0,
        'fast': 0,
        'dec': 0, 'div': 0, 'instanceof': 0, 'sl': 0, 'sr': 0, 'mod': 0, 'catch': 0, 'variadic': 0, 'function': 0,
        'user': 0,
        'xor': 0, 'args': 0, 'clone': 0, 'inherited': 0, 'unpack': 0, 'long': 0, 'lambda': 0, 'assert': 0, 'num': 0,
        'lexical': 0,
        'separate': 0, 'dynamic': 0, 'interface': 0, 'verify': 0, 'abstract': 0, 'called': 0, 'style': 0, 'set': 0,
        'const': 0, 'img': 0,
        'ticks': 0}		
		tr4w = TextRank4Keyword()  #使用TextRank4zh中的TextRank4Keyword获取关键词及其权值
		tr4w.analyze(text=opcodes, lower=True, window=5)
		for item in tr4w.get_keywords(350, word_min_len=1):
           		 for key in list_of_opcodes_dic:
                		if item.word == key:
                    			list_of_opcodes_dic[key] = item.weight
        	#print(list_of_opcodes_dic)
		TR_value=[]
		for i in list_of_opcodes_dic.values():
					TR_value.append(i)
		return TR_value

	def getEntropy(self,x):     #计算信息熵
		x_value_list = set([x[i] for i in range(x.shape[0])])
    		ent = 0.0
    		for x_value in x_value_list:
        		p = float(x[x == x_value].shape[0]) / x.shape[0]
        		logp = np.log2(p)
        		ent -= p * logp
		return ent
