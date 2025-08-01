MODEL="Salesforce/xLAM-2-32b-fc-r"
nohup vllm serve "$MODEL" \
  --enable-auto-tool-choice \
  --tool-call-parser xlam \
  --tensor-parallel-size 2 &
