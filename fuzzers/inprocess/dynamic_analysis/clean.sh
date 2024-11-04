export ANALYSIS_OUTPUT=`pwd`/analysis
rm -rf analysis/*
pushd Little-CMS
make clean
popd
