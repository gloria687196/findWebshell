## 工具简介
webshellHunter是基于findWebshell工具引入机器学习随机森林算法改进后的一款webshell检测系统，可以通过图形化用户界面，方便地检测webshell后门。

## 使用说明
###本系统通过GUI界面的按钮设定扫描路径、webshell后缀名类型以及检测开始。webshellHunter主要针对php格式的webshell进行了检测方法的改进，其他findWebshell中对于asp、aspx以及jsp格式的webshell仍为findWebshell的检测方法。
- "webshell-test-samples.zip"为webshell测试样本；
- "***.html"（多个网页文件）为作者本人自己测试工具产生的检测报告仅供参考。

   
========================================================================================================================================
————————————————————————————————————————————————————————————————————
## 开发文档（以下为findWebshell的相关开发文档）
### 字典添加
- directory目录下的sensitiveWord.py定义的是后门中的敏感关键字，可以手动添加，格式为{"关键字":"类型"}

```
php_sensitive_words = {
    "www.phpdp.org":"PHP神盾加密后门",
    "www.phpjm.net":"PHP加密后门"
}
```

- directory目录下的webshell.py定义的是webshell列表，直接添加webshell到列表里
```
php_webshell = [
"后门.php",
"xxoo.php",
"一句话.php"
]
```
### 插件开发
- 命令规范

插件命名格式：网页类型_后门类型-plugin.py

**示例**
```
php_eval_assert-plugin.py
php_preg_replace-plugin.py
asp_execute-plugin.py
```
- 函数规范和返回值

### 函数格式

    def judgeBackdoor(fileCtent)
    成功返回后门类型，失败返回None

**示例**
```
def judgeBackdoor(fileCtent):
	if keyword in fileCtent:
		result = re.compile(rule).findall(fileCtent)
		if len(result) > 0:
			return  backdoorType
	else:
		return None
```
