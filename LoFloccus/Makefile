.POSIX:
.PHONY: all x64 arm64 universal win64 icon qmake build deploy clean distclean

appbundle    = LoFloccus.app
armlib       = ${libdir}/${webdavDarwin}.arm64.a
armlibabs    = ${PWD}/${armlib}
armheader    = ${libdir}/${webdavDarwin}.arm64.h
armname      = ${webdavDarwin}.arm64.a
gosrc        = ${libdir}/libLoFloccusDav.go
gosrcabs     = ${PWD}/${gosrc}
header       = ${libdir}/${webdavDarwin}.h
icns         = assets/icon.icns
libdir       = libs
qmakeargs    = -o qmake.mk -config release \
	QMAKE_APPLE_DEVICE_ARCHS=arm64
qmakefile    = LoFloccus.pro
qmakemk      = qmake.mk
QMAKE        = qmake
universal    = ${webdavDarwin}.a
universallib = ${libdir}/${webdavDarwin}.a
webdavDarwin = libLoFloccusDavDarwin
winheader    = ${libdir}/libLoFloccusDavWin64.h
winlib       = ${libdir}/libLoFloccusDavWin64.a
winlibabs    = ${PWD}/${winlib}
x86header    = ${libdir}/${webdavDarwin}.x86_64.h
x86lib       = ${libdir}/${webdavDarwin}.x86_64.a
x86libabs    = ${PWD}/${x86lib}
x86name      = ${webdavDarwin}.x86_64.a

all: x64 arm64 universal qmake build
x64: ${x86lib}
arm64: ${armlib}
win64: ${winlib}
qmake: ${qmakemk}
universal: ${x86lib} ${armlib} ${header}
	cd ${libdir} && lipo -create -output ${universal} ${x86name} \
		${armname}
build: universal ${qmakemk} ${header} ${icns}
	make -f qmake.mk -j$$(sysctl -n hw.ncpu)
	macdeployqt LoFloccus.app -always-overwrite -verbose=1
	codesign --force --deep --sign - LoFloccus.app
clean:
	rm -rf ${x86lib} ${armlib} ${universallib} ${winlib} \
		${armheader} ${x86header} ${winheader} ${header} \
		qmake.mk .qmake.stash LoFloccus.app \
		*.o moc_* qrc_resources.* ui_lofloccus.h ${icns}
distclean: clean
	rm -rf ${appbundle}

${icns}: scripts/generate-icns-from-svg.sh
	scripts/generate-icns-from-svg.sh ${PWD}/$@
${libdir}/${webdavDarwin}.%.a: ${gosrc} scripts/build-darwin-archive.sh
	scripts/build-darwin-archive.sh $* ${PWD}/$@ ${gosrcabs}
${header}: ${armheader}
	cp ${armheader} ${header}
${winlib}: ${gosrc} scripts/build-windows-archive.sh
	scripts/build-windows-archive.sh ${winlibabs} ${gosrcabs}
${qmakemk}: ${qmakefile} ${icns}
	${QMAKE} ${qmakeargs} ${qmakefile}
