" Vim syntax file
" Language: Celestia Star Catalogs
" Maintainer: Kevin Lauder
" Latest Revision: 26 April 2008

if exists("b:current_syntax")
  finish
endif

syn keyword asciiderKeyword BOOLEAN FALSE TRUE 
syn keyword asciiderKeyword BIT_STRING NULL OCTET_STRING OBJECT_IDENTIFIER SEQUENCE INTEGER SET CHOICE PRIMITIVE
syn keyword asciiderKeyword UTCTime UTF8String PrintableString

syn match asciiderComment "#.*$"
syn match asciiderOID "\(\d\+\.\)\+\d\+"
syn match asciiderTag "\[\d\+\]"
syn region asciiderHexString start='`' end='`' contains=asciiderHex
syn match asciiderHex "\([0-9a-fA-F][0-9a-fA-F]\)\+" contained
syn region asciiderString start='"' end='"' 

let b:current_syntax = "asciider"
hi def link asciiderComment		Comment
hi def link asciiderString		Constant
hi def link asciiderHex			Type
hi def link asciiderTag			Constant
hi def link asciiderOID			Constant
hi def link asciiderKeyword		Statement
set tw=0
