#!/bin/bash

pandoc -o "$1.html" "$1.md"

text='<html>
	<head>
	<meta charset="UTF-8">
	<meta name="description" content="quackland.tk - under construction">
	<meta name="author" content="quackland.tk">
	<link rel="stylesheet" href="/styles/dracula.css">
	<script src="/js/highlight.pack.js"></script>
	<script>hljs.highlightAll();</script>
	<title>quackland.kr</title>

	<style type="text/css">
		body {
			background-color:black;
			color:white;
			font-family:hack;
			padding-left: 137px;
			padding-right: 137px;
		}
		h1 {
			font-size: 40px;
			color:#81cc4b;
			text-align: center;
		}
		h2 {
			font-size: 30px;
			color:#81cc4b;
		}
		a { color: white; }
		.hello {
			position: fixed;
			top: 50%;
			left: 50%;
			transform: translate(-50%, -50%);
		}
		.fading {
			animation:fading 7s infinite
		}
		@keyframes fading{
			0%{opacity:0}
			50%{opacity:1}
			100%{opacity:0}
		}
	</style>
</head>
<body>
'

textend="</body>
</html>
"
echo -n "$text$(cat $1.html)" > $1.html
echo -n "$textend" >> $1.html
