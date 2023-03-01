<?php

class LoginSecurityService
{
    protected static $sub_net_ips = [
        '198146'  => ['198.146.30.0/22'],
        '165225'  => ['165.50.65.0/17', '165.225.119.0/18'],
    ];

    /**
     * @param string $IP ip que VAI SER VERIFICADO
     * @param string $CIDR Mascara de ip
     * @return boolean
     */
    protected static function ipCIDRCheck($IP, $CIDR)
    {
        list($net, $mask) = split("/", $CIDR);

        $ip_net = ip2long($net);
        $ip_mask = ~((1 << (32 - $mask)) - 1);
        $ip_ip = ip2long($IP);

        $ip_ip_net = $ip_ip & $ip_mask;

        return (bool) ($ip_ip_net == $ip_net);
    }
    
    /**
     * @param string $ip_chegada ip que est? chagando para o acesso
     * @return boolean
     */
    static function checkIpRange($ip_chegada)
    {   
        try {
            $array_octetos = explode('.', $ip_chegada);

            $ip_key = "{$array_octetos[0]}{$array_octetos[1]}";

            if (array_key_exists($ip_key, self::$sub_net_ips)) {

                foreach (self::$sub_net_ips[$ip_key] as $key => $sub_net_mask) {

                    if (self::ipCIDRCheck($ip_chegada, $sub_net_mask)) return true;
                }
            }

            return false;
        } catch (Exception $e) {

            error_log("LoginSecurityService@" . __FUNCTION__);
            error_log($e->getMessage());
            return false;
        }
    }

  
}
