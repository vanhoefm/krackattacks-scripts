all: docs

%.eps: %.fig
	fig2dev -L eps $*.fig $*.eps

%.png: %.fig
	fig2dev -L png -m 3 $*.fig | pngtopnm | pnmscale 0.4 | pnmtopng \
		> $*.png

docs-pics: wpa_supplicant.png wpa_supplicant.eps hostapd.png hostapd.eps

docs: docs-pics
	(cd ..; doxygen doc/doxygen.conf; cd doc)
	$(MAKE) -C latex
	cp latex/refman.pdf wpa_supplicant-devel.pdf

html: docs-pics
	(cd ..; doxygen doc/doxygen.conf; cd doc)

clean:
	rm -f *~
	rm -f wpa_supplicant.eps wpa_supplicant.png
	rm -f hostapd.eps hostapd.png
	rm -f doxygen.warnings
	rm -rf html latex
	rm -f wpa_supplicant-devel.pdf
