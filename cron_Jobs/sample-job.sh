#!/bin/bash
#
#
#
# add this to cron tab as follows. This runs every 5 minutes
#          crontab -e
#          */5 * * * * $fun/sample-job.sh
# 
#
export core=/var/www/sand-core
export fun=/var/www/fun

cd $core/cli 
php cli.php --cl_mr=/snapshot/index/take-snapshot --PUBLIC_PATH=$fun/public/ --CODENAME=fun

