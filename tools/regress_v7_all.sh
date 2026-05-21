#!/usr/bin/env bash

cd /opt/netaiops-webhook
source venv/bin/activate

bash tools/regress_v7_1.sh || exit 2
bash tools/regress_v7_2.sh || exit 2
bash tools/regress_v7_3.sh || exit 2
bash tools/regress_v7_4.sh || exit 2
bash tools/regress_v7_5.sh || exit 2
bash tools/regress_v7_6.sh || exit 2
bash tools/regress_v7_7.sh || exit 2

printf '===== v7 all regression PASS =====\n'
