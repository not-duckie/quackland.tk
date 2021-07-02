#!/bin/bash

pandoc -o "$1.html" "$1.md"

text='<html>
	<head>
	<meta charset="UTF-8">
	<meta name="description" content="quackland.tk - under construction">
	<meta name="author" content="quackland.tk">
	<link rel="stylesheet" href="style.css">
	<link rel="stylesheet" href="styles/dracula.css">
	<script src="js/highlight.pack.js"></script>
	<script>hljs.highlightAll();</script>
	<title>quackland.kr</title>
	</head>
	<body>'

textend="</body>
</html>
"
echo -n "$text$(cat $1.html)" > $1.html
echo -n "$textend" >> $1.html
#sed 's/sourceCode\ //g' $1.html > $1.html
