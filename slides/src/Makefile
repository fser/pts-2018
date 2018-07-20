SRC:=$(wildcard *.md)
DST:=$(patsubst %.md,%.pdf, $(SRC))
THEME=Custom
all: $(DST)
$(DST): beamerthemeCustom.sty
%.pdf: %.md
	pandoc -t beamer --toc -V theme:$(THEME) -f markdown $< -o $@
