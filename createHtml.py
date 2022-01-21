#!/usr/bin/env python
#coding=utf8

head = '<html><head><meta http-equiv="Content-Type" content="text/html" charset="utf8"></head><body background="https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fpic1.win4000.com%2Fwallpaper%2F0%2F59b77acc3ba33.jpg%3Fdown&refer=http%3A%2F%2Fpic1.win4000.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=jpeg?sec=1635066368&t=527b75f378164776e89219c0d6f9117b"><h1 style="text-align:center">~~webshellHunter(DAWA-MDF方案改进findWebshell)~~</h1><h2 style="text-align:center">webshell后门检测报告</h2>' + \
'<div style="text-align:center"><table border="7" style="margin:auto; width:%80;"><tr><th>网页后门文件路径</th><th>具体后门类型</th><th>文件修改时间</th></tr>'

def createHtml(resList):
	tr = ''
	for res in resList:
		tmp = ''
		for ele in res:
			tmp += '<td>' + ele +'</td>'
		tr += '<tr>' + tmp + '</tr>'
	html = head + tr + '</table></div><h2 style="text-align:center">webshellHunter(findWebshell_plus_DAWA-MDF by ZJW)</h2></html>'
	return html
