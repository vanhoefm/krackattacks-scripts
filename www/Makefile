all: versions.png

%.png: %.fig
	fig2dev -Lpng -s5.8 -S4 -m2 $< | \
	pngtopnm | \
	pamscale -xscale 0.5 -yscale 0.5 | \
	pnmtopng > $@

%.fig: %.dot
	dot $< -Tfig -o $@

clean:
	rm versions.png versions.fig
