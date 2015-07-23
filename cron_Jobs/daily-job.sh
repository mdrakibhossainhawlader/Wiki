#!/bin/bash
#add cron job
# crontab -e
# 0 1 **** /path/to/this-script.sh

export core=/var/www/sand-core
export fun=/var/www/fun


cd $core/cli 
php cli.php --cl_mr=/snapshot/index/take-snapshot --PUBLIC_PATH=$fun/public/ --CODENAME=fun
php cli.php --cl_mr=/tag/index/update-counter-tag-all-story --PUBLIC_PATH=$fun/public/ --CODENAME=fun

