#!/usr/bin/env python2
'''
Static DOM-XSS Scanner
Authors: Axel Ekhdal and Lois Alberte Gomez Sanchez
Developed for the course Language Based Security 2017
'''
import re,os,webbrowser,html
from optparse import OptionParser

SOURCES_RE = re.compile('(location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)')
SINKS_RE = re.compile('innerHTML|write(ln)?|((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\()')
SINKS_JQUERY = re.compile('/after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\(/')

class Source(object):
	def __init__(self,start,end):
		self.start = start
		self.end = end

class Sink(object):
	def __init__(self,start,end):
		self.start = start
		self.end = end

class Line(object):
	def __init__(self,line,nLine):
		self.line = line
		self.nLine = nLine
		self.matches = []
	def addSource(self,source):
		self.matches.append(source)
	def addSink(self,sink):
		self.matches.append(sink)
	def getMatches(self):
		self.matches.sort(key=lambda x:x.end, reverse = True)
		return self.matches

class FileObject(object):
	def __init__(self, name,path):
		self.name = name
		self.path = path
		self.lines = []
	def addLine(self,line):
		self.lines.append(line)

def insertTag(data,tag,position):
	return data[:position] + tag + data[position:]

def parseFile(name,filePath):
	fileObject = FileObject(name,filePath)
	try:
		with open(filePath,'r') as f:
			for nLine,line in enumerate(f):
				l = Line(html.escape(line),nLine)
				for match in re.finditer(SOURCES_RE, html.escape(line)):
					l.addSource(Source(match.start(),match.end()))
				for match in re.finditer(SINKS_RE, html.escape(line)):
					l.addSink(Sink(match.start(),match.end()))
				for match in re.finditer(SINKS_JQUERY, html.escape(line)):
					l.addSink(Sink(match.start(),match.end()))
				fileObject.addLine(l)
	except:
		return fileObject
	return fileObject

def parseFiles(dir):
	parsedFiles = []
	rpath = os.path.realpath(dir)
	for root,dirs,files in os.walk(rpath):
		for f in files:
			if f.endswith('.js') or f.endswith('.html'):
				parsedFiles.append(parseFile(f,os.path.join(rpath,root,f)))
	generateHtml(parsedFiles, dir)

def generateHtml(files, dir):
	html = ""
	for f in files:
		html +="<tr><td>" + "<a href=\"" + f.path +"\">" + f.name + "</a></br>" + "[ "+ f.path +" ]</br></td>\n<td>"
		for line in f.lines:
			data = line.line
			for match in line.getMatches():
				data = insertTag(data,"</font>",match.end)
				if isinstance(match,Source):
					data = insertTag(data,"<font color=\"blue\">",match.start)
				else:
					data = insertTag(data,"<font color=\"red\">",match.start)
			if line.getMatches():	
				html+="[Line " + str(line.nLine) + "] " + data + "</br>\n"
	html += "</td>\n"
	generateReport(html, dir)

def generateReport(html, dir):
	path = os.path.join(os.path.realpath("template") + "/template.html")
	with open(path,'r') as f:
		template = f.read()
		report_path= os.path.join(os.getcwd() + '/report.html')
	with open(report_path,'w') as f:
		template = template.replace('{{DIRECTORY}}',os.path.realpath(dir))
		template = template.replace('{{DATA}}',html)
		f.write(template)
	webbrowser.open_new_tab(report_path)

def main():
	usage = "usage: %prog -d <dir>"
	parser = OptionParser(usage=usage)
	parser.add_option("-d","--dir", dest="dir")
	(options, args) = parser.parse_args()
	if options.dir is not None:
			parseFiles(options.dir)
	else:
		print "[Usage] analyzer.py -d <dir>"

if __name__ == '__main__':
	print "Static DOM-XSS Scanner"
	main()