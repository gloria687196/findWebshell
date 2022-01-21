#!/usr/bin/env python
#coding=utf8

import glob, os
from optparse import OptionParser
from filterShell import FilterShell
from getFileTime import getFileTime
from scanShell import *
from createHtml import createHtml
from getFeature import *
import pandas as pd
import matplotlib.pyplot as plt
import csv
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn import metrics
import pandas as pd
#below are all GUI needed dataset
from Tkinter import *
import tkMessageBox as mb
from tkFileDialog import askdirectory #from Tkinter import filedialog
import ttk #from Tkinter import ttk # 导入ttk模块，因为下拉菜单控件在ttk中
import tkMessageBox as msg #import Tkinter.messagebox as msg
import ScrolledText #from Tkinter.scrolledtext import ScrolledText
import tkFileDialog
import time
import webbrowser
from sklearn.externals import joblib

def detection(value,filepath):
#if __name__ == '__main__':
	#parser = OptionParser()	
	#parser.add_option("-p", "--path", dest="path",
		#help="input web directory filepath", metavar="PATH")
	#parser.add_option("-o", "--output", dest="output",
		#help="create a html report")
	#parser.add_option("-e", "--ext", dest="ext",
		#help="define what's file format to scan", metavar="php|asp|aspx|jsp|all")
	#(options, args) = parser.parse_args()
	after_time = time.time()
	mb.showinfo("提示","开始检测!")
	#黑名单列表
	#global blackList
	blackList = []
	#名字字典
	fileList = {}
	#结果列表
	#global resList
	resList =  []

	#检测是否输入合法的路径和要扫描的类型
	if value == None or filepath == None:#if options.ext == None or options.path == None:
		parser.error("输入的参数不正确!")
	#获取文件绝对路径
	for root, dirs, files in os.walk(filepath):#for root, dirs, files in os.walk(options.path):
		for filename in files:
			fullpath = os.path.join(root, filename)
			fileList[filename] = fullpath
			#print fullpath
	#过滤类
	#global FiltepythonrShell #FilterShell = FilterShell()
	#FilterShell = FilterShell()

	#文件名过滤
	for filename in fileList.keys():
		#res = FilterShell.filename(options.ext, filename)
		res = FilterShell.filename(value, filename)
		if res:
			#获取后门类型，文件修改时间，文件路径
			fullpath = fileList.get(filename)
			mtime = getFileTime(fullpath)
			filemode = "一般类型"
			resList.append([fullpath, filemode, mtime])
			blackList.append(fullpath)
		else:
			pass
	print("the name scan:")	
	#根据后门特征码过滤
	for filename in fileList.keys():
		fullpath = fileList.get(filename)
		if fullpath not in blackList:
			with open(fullpath, "rb") as fp:
				ctent = fp.read()
				#filemode = FilterShell.content(options.ext, ctent)
				filemode = FilterShell.content(value, ctent)
				#获取后门类型，文件修改时间，文件路径
				if filemode:
					mtime = getFileTime(fullpath)
					resList.append([fullpath, filemode, mtime])
					blackList.append(fullpath)
				else:
					pass
		else:
			pass
	print("the content scan:")	

      	#正则匹配后门语法
	#scan(options.path, options.ext, blackList, resList)
	scan(str(filepath), str(value), blackList, resList)
	print("plug scan:")	

	# Use Machine Learning(ML)    					
	rfc = joblib.load("RFC.pkl")     #读取已经使用tet1508-1305.csv特征向量集合训练好存储（借助joblib模块）的随机森林模型——RFC.pkl			
	for filename in fileList.keys():
		fullpath = fileList.get(filename)
		if fullpath not in blackList:
			rf_feature = []
			content = open(fullpath)     #从路径获取文件
			contents = content.read().split(" ")
			content.close()
			entropy = GetFeature.getEntropy(np.array(contents))     #获取文件信息熵特征
			ic = GetFeature.getIC(fullpath)     #获取文件重合指数特征
			keywords = GetFeature.getKeywords(fullpath)     #获取文件特征函数特征
			opcodes = GetFeature.recursion_trans_php_file_opcode(fullpath)     #提取文件的opcode
			TR = GetFeature.textrank_all(opcodes)     #获取opcode的TextRank特征
			for i in TR:
				rf_feature.append(i)
			for keyword in keywords:
				rf_feature.append(keyword)
			rf_feature.append(ic)
			rf_feature.append(entropy)
			prediction = rfc.predict([rf_feature])     #使用rfc模型进行判断
			opcode_string=[]
			opcode_dic=[
        'return' , 'init' , 'assign' , 'fetch' , 'fcall' , 'recv' , 'send' , 'call' , 'var' ,
        'obj' ,
        'val' , 'add' , 'jmpz' , 'method' , 'data' , 'concat' , 'icall' , 'dim' , 'jmp' , 'jmpnz' ,
        'op' , 'static' , 'ref' , 'bool' , 'array' , 'identical' , 'smaller' , 'free' , 'bind' ,
        'fe' ,
        'cast' , 'equal' , 'isempty' , 'qm' , 'isset' , 'element' , 'class' , 'constant' , 'echo' ,
        'reset' ,
        'cv' , 'type' , 'global' , 'prop' , 'unset' , 'post' , 'nop' , 'check' , 'case' , 'count' ,
        'rope' , 'eval' , 'arg' , 'silence' , 'mul' , 'bw' , 'strlen' , 'func' , 'exit' , 'ns' ,
        'include' , 'switch' , 'pre' , 'throw' , 'rw' , 'string' , 'declare' , 'list' , 'defined' ,
        'fast' ,
        'dec' , 'div' , 'instanceof' , 'sl' , 'sr' , 'mod' , 'catch' , 'variadic' , 'function' ,
        'user' ,
        'xor' , 'args' , 'clone' , 'inherited' , 'unpack' , 'long' , 'lambda' , 'assert' , 'num' ,
        'lexical' ,
        'separate' , 'dynamic' , 'interface' , 'verify' , 'abstract' , 'called' , 'style' , 'set' ,
        'const' , 'img' ,
        'ticks' ]
			if (rf_feature[63] != 0) or (rf_feature[81] != 0) or (rf_feature[88] != 0) or (rf_feature[92] != 0) or (rf_feature[93] != 0) or (rf_feature[96] != 0) or (rf_feature[97] != 0) or (rf_feature[98] != 0) or (rf_feature[99] != 0) or (rf_feature[101] != 0):
				for i in [63,81,88,92,93,96,97,98,99,101]:
					if rf_feature[i]!=0:
						opcode_string.append(opcode_dic[i-6])
				string_connect=','.join(opcode_string)			
				filemode = 'DAWA-MDF('+ string_connect +')后门'
			else:
				filemode = 'DAWA-MDF普通型后门'			
			if prediction == [1.]:
				if filemode:
					mtime = getFileTime(fullpath)
					resList.append([fullpath, filemode, mtime])
					blackList.append(fullpath)
				else:
					pass
			else:
				pass
		else:
			pass			
	print("Machine Learning scan:")		
# lines above are just a frame to be added
	print("total time:")
	print(time.time()-after_time)
	#处理后门列表
	l = len(resList)
	for i in xrange(l):
		resList[i][0] = os.path.abspath(resList[i][0])
	print(l)
	global output_name
	output_name = time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime()) 
	#生成报告
	#if options.output:
		#fp = open(options.output + '.html', 'w')
	#else:
		#fp = open('report.html', 'w')
	fp = open(output_name + '.html', 'w')
	html = createHtml(resList)
	report = []
	num = 0
	for i in resList:
		report.append(i[0])
	#print report
	#report = list(set(report))
	blackList1.set(report)
	print(len(resList))
	#print resList
	fp.write(html)
	mb.showinfo("提示","检测报告已经生成!")
	#msg.showinfo("webshell检测完成", "检测报告已经生成!")

def select_path():
    file_path = tkFileDialog.askdirectory()
    filepath1.set(file_path)
    #print('这是指定的路径', file_path)
def showwindow():
    msg.showinfo("这是点击后出现的弹窗！", "Hello nice to see you!")
def open_html():
	webbrowser.open_new_tab(output_name + '.html')	
	#webbrowser.open_new_tab('report.html')	


if __name__ == '__main__':	
	root = Tk()     #构建Tk窗体
	root.title("~webshellHunter~")
	#blackList = []#resList=[]
	filepath1 = StringVar()
	filepath1.set(' ')
	Button(root, text="选择目标路径", command=select_path).grid(row=0, column=0)
	en1 = Entry(root, textvariable=filepath1).grid(row=0, column=1, columnspan=1)
	filepath = filepath1.get()	
	value1 = StringVar()
	value1.set(' ')
	cmb = ttk.Combobox(textvariable=value1)
	cmb['value'] = ('php', 'jsp', 'asp', 'aspx','all')# 设置默认值，即默认下拉框中的内容#cmb.current(0)# 默认值中的内容为索引，从0开始
	cmb.bind("<<ComboboxSelected>>")
	cmb.grid(row=1, column=0)
	en2 = Entry(root, textvariable=value1).grid(row=1, column=1, columnspan=1)
	value = value1.get()
	FilterShell = FilterShell()
	GetFeature = GetFeature()
	blackList1 = StringVar()
	blackList1.set(' ')
	Button(root, text='开始检测', command=lambda:detection(value=value1.get(),filepath=filepath1.get())).grid(row=2, column=0, columnspan=2)#run detecting
	lab = Label(root,text = 'Detection Result')
	lab.grid(row=5, column=0,columnspan=2)
	ls = Listbox(root,listvariable=blackList1,width=65)#st = ScrolledText.ScrolledText(root, width=40, height=20, background='#ffffff')	
	#blackList = blackList1.get()
	#for i in blackList:
		#ls.insert(END,i)
	ls.grid(row=6, column=0, columnspan=2)
	Button(root, text="打开检测报告",command=open_html).grid(row=7, column=0, columnspan=2)
	root.mainloop()
