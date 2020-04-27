<?php
namespace Seven\Fingerprint;

use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\DeviceParserAbstract;

class FingerprintGenerator
{
    /**
     * Returns a SHA1 hash based on user agent an IP
     * @param string $userAgent
     * @param string $ip
     * @return string
     */
    public static function generate(string $userAgent, string $ip): string
    {
        DeviceParserAbstract::setVersionTruncation(DeviceParserAbstract::VERSION_TRUNCATION_NONE);

        $dd = new DeviceDetector($userAgent);
        $dd->parse();

        $fingerprint = $dd->getOs('name') .
            $dd->getOs('version') .
            $dd->getDeviceName() .
            $dd->getBrandName() .
            $dd->getModel() .
            $ip;

        return sha1($fingerprint);
    }
}
