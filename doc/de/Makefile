MAN_TXT = $(wildcard *.txt)
MAN = $(patsubst %.txt,%,$(MAN_TXT))
XML = $(patsubst %,%.xml,$(MAN))

man: $(MAN)

%.1 %.2 %.3 %.4 %.5 %.6 %.7 %.8 : %.*.txt
	$(RM) $@ $@.xml
	a2x -a lang=de -d manpage -f manpage $<

clean:
	$(RM) $(MAN) $(XML)
