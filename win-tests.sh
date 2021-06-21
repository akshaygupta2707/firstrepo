#!/usr/bin/env bash

################################################################################
#
# This Shell Script is created to perform UAT of Flexible Engine Windows OS Images
#
################################################################################
################################################################################
#
# Author :  ocbcsd.skcos&caas@orange.com
#
################################################################################

if [ -z "$*" ];then
    echo "Usage: ./test-cases.sh <Image name or image ID>"
    exit 1
fi

IMAGE=$*
image_status=$(openstack image list -c Name -f value|grep -ci "$*")
if [ "$image_status" -eq 0 ];then
    echo "No such image exists. Verify and rerun tests."
    exit 1
fi

eip=$(openstack floating ip create 0a2228f2-7f8a-45f1-8e09-9039e1d09975 -c floating_ip_address -f value)
if [ -z "$eip" ];then
    echo "Quota exceeded for EIP. Release an EIP and rerun tests."
    exit 1
fi

WD="$(pwd)"

pre_steps(){
    local server_key server_old port_old port_ip server_port volume_old server_vol
    server_key="$(openstack keypair list -c Name -f value|grep -c testkey)"
    if [ "$server_key" -eq 1 ];then
        openstack keypair delete testkey
    fi

    server_old="$(openstack server list -c ID -c Name -f value |grep test-ecs|awk '{print $1}')"
    if [ -n "$server_old" ];then
        openstack server delete --wait "$server_old"
    fi

    port_old="$(openstack port list -f value |grep fe-test-port| awk '{print $1}')"
    if [ -n "$port_old" ];then
        openstack port delete "$port_old"
    fi
    port_ip=$(openstack port show fe-test-port -c fixed_ips -f value| awk -F "=" '{print $2}'| cut -d "'" -f 2)
    if [ -n "$port_ip" ];then
        server_port=$(openstack server list -f table|grep "$port_ip" | awk '{print $2}')
        if [ -n "$server_port" ];then
            openstack server remove port "$server_port" fe-test-port
            openstack port delete "$port_old"
            openstack server delete --wait "$server_port"
        fi
    fi

    volume_old="$(openstack volume list -f value|grep fe-test-volume| awk '{print $1}')"
    if [ -n "$volume_old" ];then
        openstack volume delete "$volume_old"
    fi
    server_vol="$(openstack volume show fe-test-volume -c attachments -f yaml|grep server_id|awk '{print $2}')"
    if [ -n "$server_vol" ];then
        openstack server delete --wait "$server_vol"
        openstack volume delete "$volume_old"
    fi

    rm -rf "${WD:?}/"keys
    rm fe_test_report.txt
    rm win-report.py win-output.txt firewall-state.py  lang-pack.py  patch-status.py
    mkdir -p "$WD"/keys
    KEY_DIR="$(cd "$WD"/keys && pwd)"
    export KEY_DIR

    openstack keypair create testkey > "$KEY_DIR"/testkey.pem
    if [ -f "$KEY_DIR"/testkey.pem ];then
        chmod -R 600 "${KEY_DIR:?}/"*
    fi

    cat >>"$WD"/fe_test_report.txt <<EOL
                                                    FE TEST REPORT
########################################################################################################################

+++++++++++++++++++++++++++++++++++++++++++++++++++++++
+   Date: %time%
+   Start Time: %time_start%
+   End Time: %time_end%
+   Image Name: %image%
+++++++++++++++++++++++++++++++++++++++++++++++++++++++

========================================================================================================================
S.no |   TEST                                                                   |         RESULT
========================================================================================================================
1.   |   Start ECS                                                              |         %test1%
2.   |   Stop active ECS                                                        |         %test2%
3.   |   Restart ECS                                                            |         %test3%
4.   |   Check ECS active from restart                                          |         %test4%
5.   |   Attach EIP                                                             |         %test14%
6.   |   Check WinRM connection                                                 |         %test5%
7.   |   Add NIC to ECS                                                         |         %test6%
8.   |   Check additional NIC in ECS                                            |         %test7%
9.   |   Remove additional NIC from ECS                                         |         %test8%
10.  |   Check additional NIC removed from ECS                                  |         %test17%
11.  |   Add disk to ECS                                                        |         %test9%
12.  |   Check additional disk attached in ECS                                  |         %test10%
13.  |   Detach additional disk from ECS                                        |         %test11%
14.  |   Check additional disk removed from ECS                                 |         %test12%
15.  |   Check licensing status for ECS                                         |         %test16%
16.  |   Check Shinken status in ECS                                            |         %test18%
========================================================================================================================

Additional Tests =>
EOL

    sed -i -e "s/%time%/$(TZ=IST-5:30 date +%F)/g" "$WD"/fe_test_report.txt
    sed -i -e "s/%time_start%/$(TZ=IST-5:30 date +%T)/g" "$WD"/fe_test_report.txt
    sed -i -e 's/%image%/'"$IMAGE"'/g' "$WD"/fe_test_report.txt
}

test1(){
    echo "TEST: Start ECS"

    # Start ECS
    local status server_id
    status=$(openstack server list -c Name -f value|grep -c test-ecs)
    if [ "$status" -gt 0 ]; then
        server_id=$(openstack server list -c ID -c Name -f value |grep test-ecs|awk '{print $1}')
        openstack server delete --wait "$server_id"
        status=$(openstack server list -c Name -f value|grep -c test-ecs)
    fi

    openstack -q --insecure server create --flavor s1.xlarge --image "$IMAGE" \
    --key-name testkey --nic net-id=1fd7a904-2367-4a43-ae49-1351588387d6 --security-group default --wait test-ecs

    status=$(openstack server list -c Name -f value|grep -c test-ecs)
    if [ "$status" -eq 1 ];then
        echo "TEST: Start ECS => PASS"
        sed -i "s/%test1%/PASS/g" "$WD"/fe_test_report.txt
        get_password
        test2
        test3_4
    else
        echo "TEST: Start ECS => FAIL"
        echo "Unable to start ECS"
        sed -i "s/%test1%/FAIL/g" "$WD"/fe_test_report.txt
    fi
}

get_password(){
    sleep 100
    status=$(openstack server show test-ecs -c status -f value)
    if [ "$status" = "ACTIVE" ]; then
        TOKEN=$(openstack token issue -c id -f value)
        ID=$(openstack server show test-ecs -c id -f value)
        pswdjson=$(curl -s -X GET "https://ecs.$OS_REGION_NAME.prod-cloud-ocb.orange-business.com/v2/$OS_PROJECT_ID/servers/$ID/os-server-password" -H 'Content-Type: application/json' -H 'Accept: application/json' -H "X-Auth-Token: $TOKEN" -H 'X-Language: en-us')
        pswd_value=$(echo "$pswdjson" | jq --raw-output '.[]')
        password=$(echo "$pswd_value"| openssl base64 -d -A | openssl rsautl -decrypt -inkey "$KEY_DIR"/testkey.pem)
        export password
    else
        echo "Check ECS state"
    fi
    if [ -n "$password" ]; then
        test14
    else
        echo "Cannot fetch password"
    fi
}

test2(){
    echo "TEST: Stop active ECS"

    local pre_status status
    pre_status=$(openstack server show test-ecs -c status -f value)
    if [[ "$pre_status" = "ACTIVE" ]]; then
        local counterA=0 
        local counterB=0
        until [[ "$status" = "SHUTOFF" ]];do
            if [ $counterA -eq 0 ];then
              openstack -q server stop test-ecs
              ((counterA++))
            fi
            status=$(openstack server show test-ecs -c status -f value)
            sleep 10
            ((counterB++))
            if [ "$counterB" -eq 25 ];then
                break
            fi
        done
    fi

    status=$(openstack server show test-ecs -c status -f value)
    if [[ "$status" = "SHUTOFF" ]];then
        echo "TEST: Stop active instance => PASS"
        sed -i "s/%test2%/PASS/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterB" -eq 25 ];then
        echo "TEST: Stop active instance => FAIL"
        echo "TIMEOUT: Unable to stop ECS"
        sed -i "s/%test2%/FAIL/g" "$WD"/fe_test_report.txt
    fi
}

test3_4(){
    echo "TEST: Restart ECS"

    local pre_status status server_id
    pre_status=$(openstack server show test-ecs -c status -f value)

    if [[ "$pre_status" = "SHUTOFF" ]]; then
        local counterA=0
        local counterB=0
        until [[ "$status" = "ACTIVE" ]];do
            if [[ $counterA -eq 0 ]];then
                openstack server start test-ecs
                ((counterA++))
            fi
            status=$(openstack server show test-ecs -c status -f value)
            sleep 10
            ((counterB++))
            if [ "$counterB" -eq 25 ];then
                break
            fi
        done
    fi

    server_id=$(openstack server show test-ecs -c id -f value)
    pre_status=$(openstack server show test-ecs -c status -f value)

    local counterA=0
    local counterC=0
    if [[ "$pre_status" = "ACTIVE" ]]; then
        until [ "$status" = "REBOOT" ];do
            if [ $counterA -eq 0 ];then
                openstack server reboot test-ecs
                ((counterA++))
            fi
            status=$(openstack server show test-ecs -c status -f value)
            sleep 2
            ((counterC++))
            if [ "$counterC" -eq 10 ];then
                break
            fi
        done
    fi

    if [[ "$status" = "REBOOT" ]];then
        echo "TEST: Restart ECS => PASS"
        sed -i "s/%test3%/PASS/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterB" -eq 25 ];then
        echo "TEST: Restart ECS => FAIL"
        echo "TIMEOUT: Unable to start stopped ECS"
        sed -i "s/%test3%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterC" -eq 10 ];then
        echo "TEST: Restart ECS => FAIL"
        echo "TIMEOUT: Unable to reboot ECS"        
        sed -i "s/%test3%/FAIL/g" "$WD"/fe_test_report.txt
    fi


    echo "TEST: Check ECS active from restart"
    local counterA=0
    if [ "$status" != "ACTIVE" ]; then
        until [ "$status" = "ACTIVE" ];do
        status=$(openstack server show test-ecs -c status -f value)
        sleep 10
        ((counterA++))
        if [ "$counterA" -eq 25 ];then
            break
        fi        
        done
    fi
    if [[ "$status" = "ACTIVE" ]];then
        echo "TEST: Check ECS active from restart => PASS"
        sed -i "s/%test4%/PASS/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterA" -eq 25 ];then
        echo "TEST: Check ECS active from restart => FAIL"
        sed -i "s/%test4%/FAIL/g" "$WD"/fe_test_report.txt
    fi
}

test14(){
    echo "TEST: Attach EIP to ECS"
    
    local pre_status status
    pre_status=$(openstack server show test-ecs -c addresses -f value|awk -F "=" '{print $2}'|awk -F "," '{print $2}'|sed 's/ //g')
    if [ -z "$pre_status" ];then
        openstack server add floating ip test-ecs "$eip"
    else
        echo "EIP already exists on ECS"
    fi

    local counterA=0
    until [ -n "$status" ];do
        status=$(openstack server show test-ecs -c addresses -f value|awk -F "=" '{print $2}'|awk -F "," '{print $2}'|sed 's/ //g')
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            break
        fi        
    done
    if [ -n "$status" ];then
        echo "TEST: Attach EIP => PASS"
        sed -i "s/%test14%/PASS/g" "$WD"/fe_test_report.txt
        test5
    fi
    if [ "$counterA" -eq 10 ];then
        echo "TEST: Attach EIP => FAIL"
        echo "Unable to attach EIP to ECS"
        sed -i "s/%test14%/FAIL/g" "$WD"/fe_test_report.txt
    fi    
}

test5(){
    echo "TEST: Check WinRM connection"
    sleep 100
    if ! nc -w 120s -z "$eip" 5985;then
        sed -i "s/%test5%/FAIL/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test5%/PASS/g" "$WD"/fe_test_report.txt
        test67_910_18
        test817_1112
        additional_tests
    fi
}

test67_910_18(){
    echo "TEST: Attach NIC and disk to ECS and check it in instance"

    local az server_id volume_id status status2 nics disks lic
    openstack port create --network 1fd7a904-2367-4a43-ae49-1351588387d6 fe-test-port
    sleep 5
    openstack server add port test-ecs fe-test-port
    sleep 5
    local counterA=0
    until [[ $status -eq 2 ]];do
        status=$(openstack server show test-ecs -c addresses -f value |awk -F "=" '{print $2}'|tr -cd ,|wc -c)
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            echo "TIMEOUT: Unable to check attached port on ECS"
            break
        fi
    done
    if [ "$status" -eq 2 ];then
        echo "TEST:Add NIC to ECS => PASS"
        sed -i "s/%test6%/PASS/g" "$WD"/fe_test_report.txt
    else
        echo "TEST: Add NIC to ECS => FAIL"
        sed -i "s/%test6%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterA" -eq 10 ];then
        echo "TEST: Add NIC to ECS => FAIL"
        echo "Unable to attach EIP to ECS"
        sed -i "s/%test6%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    
    local status2
    local counterA=0
    az="$(openstack server show test-ecs -c OS-EXT-AZ:availability_zone -f value)"
    server_id="$(openstack server show test-ecs -c id -f value)"
    openstack volume create fe-test-volume --size 10 --availability-zone "$az"
    sleep 10
    local counterA=0
    until [ -n "$volume_id" ];do
        volume_id=$(openstack volume show fe-test-volume -c id -f value)
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            echo "Unable to get EVS volume id"
            break
        fi        
    done
    openstack server add volume "$server_id" "$volume_id"
    local counterA=0
    until [[ $status2 -eq 1 ]];do
        status2=$(openstack server show test-ecs -c volumes_attached -f value|grep -c "$volume_id")
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            echo "TIMEOUT: Unable to check attached disk on ECS"
            break
        fi
    done
    if [ "$status2" -eq 1 ];then
        echo "TEST: Add disk to ECS => PASS"
        sed -i "s/%test9%/PASS/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterA" -eq 10 ];then
        echo "TEST: Add disk to ECS => FAIL"
        echo "Unable to attach EIP to ECS"
        sed -i "s/%test9%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    sleep 100
    pip3 -q install --user winrm
    curl https://gist.githubusercontent.com/nvntsin/d56bbd2725447c48a0ab03047ec27d4f/raw/f33f01cd2bb40ad840470af31748f2ce17200235/win-report.py -o win-report.py
    sed -i "s/%ip%/$eip/g" "$WD"/win-report.py
    sed -i "s/%pswd%/$password/g" "$WD"/win-report.py
    python3 win-report.py
    sleep 10
    nics=$(grep -ci index win-output.txt)
    disks=$(grep -ci physical win-output.txt)
    lic=$(grep -C3 LicenseStatus win-output.txt| grep -ci windows)
    shin=$(grep nscp_ocb win-output.txt| grep -ci run)
    if [ "$nics" -gt  1 ];then
        sed -i "s/%test7%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test7%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$disks" -gt  1 ];then
        sed -i "s/%test10%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test10%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$lic" -eq  1 ];then
        sed -i "s/%test16%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test16%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$shin" -eq  1 ];then
        sed -i "s/%test18%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test18%/FAIL/g" "$WD"/fe_test_report.txt
    fi
}

test817_1112(){
    echo "TEST: Remove NIC and disk from ECS and check it in instance"

    local server_id volume_id status status2 nics disks
    openstack server remove port test-ecs fe-test-port
    sleep 5
    local counterA=0
    until [[ $status -eq 1 ]];do
        status=$(openstack server show test-ecs -c addresses -f value |awk -F "=" '{print $2}'|tr -cd ,|wc -c)
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            echo "TIMEOUT: Unable to check attached port on ECS"
            break
        fi
    done
    if [ "$status" -eq 1 ];then
        echo "TEST:Remove NIC from ECS => PASS"
        sed -i "s/%test17%/PASS/g" "$WD"/fe_test_report.txt
    else
        echo "TEST: Add NIC to ECS => FAIL"
        sed -i "s/%test17%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterA" -eq 10 ];then
        echo "TEST: Remove NIC from ECS => FAIL"
        echo "Unable to attach EIP to ECS"
        sed -i "s/%test17%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    
    local counterA=0
    server_id="$(openstack server show test-ecs -c id -f value)"
    volume_id=$(openstack volume show fe-test-volume -c id -f value)
    openstack server remove volume "$server_id" "$volume_id"
    sleep 10
    local counterA=0
    until [[ -z $status2 ]];do
        status2=$(openstack server show test-ecs -c volumes_attached -f value|grep -c "$volume_id")
        sleep 5
        ((counterA++))
        if [ "$counterA" -eq 10 ];then
            echo "TIMEOUT: Unable to check attached disk on ECS"
            break
        fi
    done
    if [ -z "$status2" ];then
        echo "TEST: Detach additional disk from ECS => PASS"
        sed -i "s/%test11%/PASS/g" "$WD"/fe_test_report.txt
    fi
    if [ "$counterA" -eq 10 ];then
        echo "TEST: Detach additional disk from ECS => FAIL"
        echo "Unable to attach EIP to ECS"
        sed -i "s/%test11%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    sleep 100
    python3 win-report.py
    nics=$(grep -ci index win-output.txt)
    disks=$(grep -ci physical win-output.txt)
    if [ "$nics" -eq  1 ];then
        sed -i "s/%test8%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test8%/FAIL/g" "$WD"/fe_test_report.txt
    fi
    if [ "$disks" -eq  1 ];then
        sed -i "s/%test12%/PASS/g" "$WD"/fe_test_report.txt
    else
        sed -i "s/%test12%/FAIL/g" "$WD"/fe_test_report.txt
    fi 
}

additional_tests(){
    curl https://gist.githubusercontent.com/nvntsin/3fb6db7382e046380784fc68a4caf5cc/raw/dd8438b523e68febe7c0a6589628307a2bf91419/firewall-state.py -o firewall-state.py
    sed -i "s/%ip%/$eip/g" "$WD"/firewall-state.py
    sed -i "s/%pswd%/$password/g" "$WD"/firewall-state.py
    python3 firewall-state.py

    curl https://gist.githubusercontent.com/nvntsin/f2c4f1dac4d4d24f62bbdb56a05bd18e/raw/432c85679ff7e1400dd1e754b960f77b9cd8bb8c/lang-pack.py -o lang-pack.py
    sed -i "s/%ip%/$eip/g" "$WD"/lang-pack.py
    sed -i "s/%pswd%/$password/g" "$WD"/lang-pack.py
    python3 lang-pack.py

    curl https://gist.githubusercontent.com/nvntsin/8a382181f16dde0a015c5ea797768fd9/raw/e11e7d88e8581b8b985991f87f7b26039c2845df/patch-status.py -o patch-status.py
    sed -i "s/%ip%/$eip/g" "$WD"/patch-status.py
    sed -i "s/%pswd%/$password/g" "$WD"/patch-status.py
    python3 patch-status.py
}

clean_up(){
    echo "Final Cleanup"
    
    openstack floating ip delete "$eip"

    local server_key server_old port_old port_ip volume_old server_vol server_port
    
    server_key="$(openstack keypair list -c Name -f value|grep -c testkey)"
    if [ "$server_key" -eq 1 ];then
        openstack keypair delete testkey
    fi

    server_old="$(openstack server list -c ID -c Name -f value |grep test-ecs|awk '{print $1}')"
    if [ -n "$server_old" ];then
        openstack server delete --wait "$server_old"
    fi

    port_old="$(openstack port list -f value |grep fe-test-port| awk '{print $1}')"
    if [ -n "$port_old" ];then
        openstack port delete "$port_old"
    fi
    port_ip=$(openstack port show fe-test-port -c fixed_ips -f value| awk -F "=" '{print $2}'| cut -d "'" -f 2)
    if [ -n "$port_ip" ];then
        server_port=$(openstack server list -f table|grep "$port_ip" | awk '{print $2}')
        if [ -n "$server_port" ];then
            openstack server remove port "$server_port" fe-test-port
            openstack port delete "$port_old"
            openstack server delete --wait "$server_port"
        fi
    sleep 3
    fi

    volume_old="$(openstack volume list -f value|grep fe-test-volume| awk '{print $1}')"
    if [ -n "$volume_old" ];then
        openstack volume delete "$volume_old"
    fi
    server_vol="$(openstack volume show fe-test-volume -c attachments -f yaml|grep server_id|awk '{print $2}')"
    if [ -n "$server_vol" ];then
        openstack server delete --wait "$server_vol"
        openstack volume delete "$volume_old"
    fi
    sleep 3

    rm -rf "${WD:?}/"keys
    rm win-report.py win-output.txt firewall-state.py  lang-pack.py  patch-status.py

    while IFS='' read -r line || [[ -n "$line" ]]; do
        for i in {1..18};do
            sed -i -e "s/%test$i%/FAILED_TO_RUN/g" "$WD"/fe_test_report.txt
        done         
    done < "$WD"/fe_test_report.txt

    sed -i -e "s/%time_end%/$(TZ=IST-5:30 date +%T)/g" "$WD"/fe_test_report.txt  
    cat "$WD"/fe_test_report.txt
}

#Final call on functions
pre_steps   #Prepare Setup
test1       #Start ECS -> Get password -> Attach EIP
clean_up    #Clean Setup