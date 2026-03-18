<?php

/**
 * DN Helper for misc ASN1 classes
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\Common\Traits;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Hash;
use phpseclib4\Exception\CharacterConversionException;
use phpseclib4\Exception\InvalidArgumentException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\BaseString;
use phpseclib4\File\ASN1\Types\BaseType;
use phpseclib4\File\ASN1\Types\Choice;
//use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\File\ASN1\Types\UTF8String;

/**
 * Extension Helper for misc ASN1 classes
 *
 * Used by X509 and CRL
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait DN
{
    /**
     * Return internal array representation
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_ARRAY = 0;
    /**
     * Return string
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_STRING = 1;
    /**
     * Return ASN.1 name string
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_ASN1 = 2;
    /**
     * Return OpenSSL compatible array
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_OPENSSL = 3;
    /**
     * Return canonical ASN.1 RDNs string
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_CANON = 4;
    /**
     * Return name hash for file indexing
     *
     * @see \phpseclib4\File\X509::getDN()
     */
    const DN_HASH = 5;

    public static function mapInDNs(array|Constructed &$dn): void
    {
        ASN1::disableCacheInvalidation();

        if ("$dn[type]" == 'id-at-postalAddress') {
            $dn['value'] = ASN1::map(ASN1::decodeBER($dn['value']->getEncoded()), Maps\PostalAddress::MAP);
            // if we swapped out the above line for the following code then
            // $cert['tbsCertificate']['subject']['rdnSequence'][0][0]['value'] would be an array vs a BaseType
            // object and ->getEncoded() wouldn't work
            /*
            $temp = ASN1::map(ASN1::decodeBER($dn['value']->getEncoded()), Maps\PostalAddress::MAP);
            $dn['value'] = [];
            foreach ($temp as $key => $part) {
                $dn['value'][] = current($part->toArray());
            }
            */
        }

        ASN1::enableCacheInvalidation();
    }

    private static function mapOutDNsInner(array|Constructed &$dns): void
    {
        $size = count($dns);
        for ($i = 0; $i < $size; $i++) {
            if (!isset($dns[$i])) {
                continue;
            }

            for ($j = 0; $j < count($dns[$i]); $j++) {
                $type = $dns[$i][$j]['type'];
                $value = &$dns[$i][$j]['value'];

                if ($value instanceof Element) {
                    continue;
                }

                self::encodeDNS($type, $value);
                if (is_array($value)) {
                    // maybe we should create an UnableToMapException ?
                    throw new RuntimeException("An unmappable array was encountered for $type");
                }
            }
        }
    }

    private static function encodeDNS(OID|string $type, BaseType|array|string &$value): void
    {
        if ($type == 'id-at-postalAddress') {
            if ($value instanceof BaseType) { // eg. if it's Constructed
                ASN1::encodeDER($value, Maps\PostalAddress::MAP);
            } else {
                foreach ($value as &$val) {
                    if ($val instanceof BaseType) {
                        $class = (new \ReflectionClass($val::CLASS))->getShortName();
                        $key = match ($class) {
                            'TeletexString' => 'teletexString',
                            'PrintableString' => 'printableString',
                            'UniversalString' => 'universalString',
                            'UTF8String' => 'utf8String',
                            'BMPString' => 'bmpString',
                            default => null
                        };
                        if (!isset($key)) {
                            throw new RuntimeException("$class is not a supported value for id-at-postalAddress");
                        }
                        $val = [$key => $val];
                    } elseif (is_string($val)) {
                        $val = ['utf8String' => new UTF8String($val)];
                    } elseif ($val instanceof Element) {
                        $val = ['utf8String' => $val];
                    } elseif (!is_array($val)) {
                        throw new RuntimeException('Invalid value for id-at-postalAddress encountered');
                    }
                }
                $temp = ASN1::encodeDER($value, Maps\PostalAddress::MAP);
                // we do this so that a print_r on the X509 object after string conversion
                // will still show something human readable
                $value = ASN1::map(ASN1::decodeBER($temp), Maps\PostalAddress::MAP);
            }
            $value->enableForcedCache();
        }
    }

    /**
     * "Normalizes" a Distinguished Name property
     */
    private static function translateDNProp(string $propName): string
    {
        // allow raw OIDs through
        if (preg_match('#^\d+(?:\.\d+)+$#', $propName)) {
            return $propName;
        }

        return match (strtolower($propName)) {
            'jurisdictionofincorporationcountryname', 'jurisdictioncountryname', 'jurisdictionc' => 'jurisdictionOfIncorporationCountryName',
            'jurisdictionofincorporationstateorprovincename', 'jurisdictionstateorprovincename', 'jurisdictionst' => 'jurisdictionOfIncorporationStateOrProvinceName',
            'jurisdictionlocalityname', 'jurisdictionl' => 'jurisdictionLocalityName',
            'id-at-businesscategory', 'businesscategory' => 'id-at-businessCategory',
            'id-at-countryname', 'countryname', 'c' => 'id-at-countryName',
            'id-at-organizationname', 'organizationname', 'o' => 'id-at-organizationName',
            'id-at-dnqualifier', 'dnqualifier' => 'id-at-dnQualifier',
            'id-at-commonname', 'commonname', 'cn' => 'id-at-commonName',
            'id-at-stateorprovincename', 'stateorprovincename', 'state', 'province', 'provincename', 'st' => 'id-at-stateOrProvinceName',
            'id-at-localityname', 'localityname', 'l' => 'id-at-localityName',
            'id-at-emailaddress', 'id-emailaddress', 'emailaddress' => 'pkcs-9-at-emailAddress',
            'id-at-serialnumber', 'serialnumber' => 'id-at-serialNumber',
            'id-at-postalcode', 'postalcode' => 'id-at-postalCode',
            'id-at-streetaddress', 'streetaddress' => 'id-at-streetAddress',
            'id-at-name', 'name' => 'id-at-name',
            'id-at-givenname', 'givenname', 'gn' => 'id-at-givenName',
            'id-at-surname', 'surname', 'sn' => 'id-at-surname',
            'id-at-initials', 'initials' => 'id-at-initials',
            'id-at-generationqualifier', 'generationqualifier' => 'id-at-generationQualifier',
            'id-at-organizationalunitname', 'organizationalunitname', 'ou' => 'id-at-organizationalUnitName',
            'id-at-organizationidentifier', 'organizationIdentifier' => 'id-at-organizationIdentifier',
            'id-at-pseudonym', 'pseudonym' => 'id-at-pseudonym',
            'id-at-title', 'title' => 'id-at-title',
            'id-at-description', 'description' => 'id-at-description',
            'id-at-role', 'role' => 'id-at-role',
            'id-at-uniqueidentifier', 'uniqueidentifier', 'x500uniqueidentifier' => 'id-at-uniqueIdentifier',
            'postaladdress', 'id-at-postaladdress' => 'id-at-postalAddress',
            'dc', 'domaincomponent', 'id-domaincomponent' => 'id-domainComponent',
            default => throw new InvalidArgumentException("$propName is not a supported distinguished name attribute"),
        };
    }

    // if you want to replace a DN prop you should do removeDNProp and then addDNProp
    // i think adding addDNProps (plural) would be good too.
    // so removeDNProps(), addDNProps(), addDNProp()
    private static function addDNPropsInternal(array|Choice &$dn, string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        $propName = self::translateDNProp($propName);
        if ($propName == 'id-at-postalAddress' && is_string($value) && preg_match('/^#(?:[0-9A-Fa-f][0-9A-Fa-f])+$/', $value)) {
            $temp = [
                'type' => $propName,
                'value' => new Element(pack('H*', substr($value, 1)))
            ];
            self::mapInDNs($temp);
            $dn['rdnSequence'][] = [$temp];
            return;
        }

        $dn['rdnSequence'][] = [
            [
                'type' => $propName,
                'value' => $value
            ]
        ];
    }

    private static function hasDNPropsInternal(array|Choice $dn, string $propName): bool
    {
        $propName = self::translateDNProp($propName);

        $rdn = &$dn['rdnSequence'];
        $size = count($rdn);
        for ($i = 0; $i < $size; $i++) {
            if ($rdn[$i][0]['type'] == $propName) {
                return true;
            }
        }
        return false;
    }

    private static function removeDNPropsInternal(array|Choice &$dn, string $propName): void
    {
        $propName = self::translateDNProp($propName);

        $rdn = &$dn['rdnSequence'];
        $size = count($rdn);
        for ($i = 0; $i < $size; $i++) {
            if ($rdn[$i][0]['type'] == $propName) {
                unset($rdn[$i]);
            }
        }
    }

    private static function setDNInternal(array|Choice &$dn, array|string|Element $props): void
    {
        $dn['rdnSequence'] = [];

        if ($props instanceof Element) {
            $dn = $props;
            return;
        }

        if (empty($props)) {
            $props = ['rdnSequence' => []];
        }

        if (is_array($props)) {
            if (isset($props['rdnSequence'])) {
                $dn = $props;
                return;
            }

            // handles stuff generated by openssl_x509_parse()
            foreach ($props as $prop => $value) {
                if (!is_array($value)) {
                    self::addDNPropsInternal($dn, $prop, $value);
                } else {
                    foreach ($value as $val) {
                        self::addDNPropsInternal($dn, $prop, $val);
                    }
                }
            }
            return;
        }

        if (preg_match('#[^\x20-\x7E]#', $props)) {
            throw new RuntimeException('Non-printable ASCII characters should not be present');
        }

        // openssl_x509_parse() with OpenSSL 3.0+ returns this format
        // this is the default format of OpenSSL's X509_get_subject_name() method
        //    per https://zakird.com/2013/10/13/certificate-parsing-with-openssl
        if ($props[0] == '/') {
            $props = preg_split('#(?<!\\\\)(?:\\\\\\\\)*/#', $props);
            array_shift($props);
            foreach ($props as $prop) {
                preg_match('#(^[a-zA-Z0-9\.]+)=(.*)#', $prop, $match);
                $propName = $match[1];
                $propValue = $match[2];
                $propValue = str_replace('\/', '/', $propValue);
                $callback = fn ($x): string => chr(hexdec((string) $x[1]));
                $propValue = preg_replace_callback('#\\\x([0-9A-Fa-f]{2})#', $callback, $propValue);
                $temp = [
                    'type' => self::translateDNProp($propName),
                    'value' => new Element($propValue)
                ];
                self::mapInDNs($temp);
                if (!$temp['value'] instanceof Element) {
                    $propValue = $temp['value'];
                }
                self::addDNPropsInternal($dn, $propName, $propValue);
            }
            return;
        }

        // the following is the format that OpenSSL's CLI implementation (3.0+) outputs
        $doubleQuoteStringPattern = '#"(?:(?:[^"\\\]|\\\.)*)"#';
        preg_match_all($doubleQuoteStringPattern, $props, $matches);
        $props = preg_replace($doubleQuoteStringPattern, "\n", $props);
        $props = explode(',', (string) $props);
        foreach ($props as &$prop) {
            $prop = ltrim($prop);
            if (str_contains($prop, "\n")) {
                $match = array_shift($matches[0]);
                $prop = str_replace("\n", $match, $prop);
            }
        }
        unset($prop);

        foreach ($props as $prop) {
            if (!preg_match('#(^[a-zA-Z0-9\.]+)[ ]?=[ ]?(.*)#', $prop, $match)) {
                throw new RuntimeException('DNs should be in either a /C=whatever/O=whatever format or a "C = whatever, O = whatever" format (without the double quotes)');
            }
            $propName = $match[1];
            $propValue = $match[2];

            if (preg_match('/^#(?:[0-9A-Fa-f][0-9A-Fa-f])+$/', $propValue)) {
                $temp = [
                    'type' => self::translateDNProp($propName),
                    'value' => new Element(pack('H*', substr($propValue, 1)))
                ];
                self::mapInDNs($temp);
                self::addDNPropsInternal($dn, $propName, $temp['value']);
                continue;
            }

            // remove double quotes if present
            if ($propValue[0] == '"') {
                $propValue = substr($propValue, 1, -1);
            }
            // restore non-printable ascii
            $callback = fn ($x): string => chr(hexdec((string) $x[1]));
            $propValue = preg_replace_callback('#\\\([0-9A-Fa-f]{2})#', $callback, $propValue);
            // replace \" with " and \\ with \
            $propValue = str_replace(['\"', '\\\\'], ['"', '\\'], $propValue);
            self::addDNPropsInternal($dn, $propName, $propValue);
        }
    }

    // this should prob be moved to an interface
    private static function formatDN(array|Choice $dn, int $format): array|string
    {
        switch ($format) {
            case self::DN_ARRAY:
                self::mapOutDNsInner($dn['rdnSequence']);
                $dn = ASN1::encodeDER($dn, Maps\Name::MAP);
                $dn = ASN1::decodeBER($dn);
                $rules = [];
                $rules['rdnSequence']['*']['*'] = self::mapInDNs(...);
                $dn = ASN1::map($dn, Maps\Name::MAP, $rules);
                return $dn->toArray();
            case self::DN_ASN1:
                self::mapOutDNsInner($dn['rdnSequence']);
                return ASN1::encodeDER($dn, Maps\Name::MAP);
            case self::DN_CANON:
                // No SEQUENCE around RDNs and all string values normalized as
                // trimmed lowercase UTF-8 with all spacing as one blank.
                // constructed RDNs (save for id-at-postalAddress) will not be canonicalized
                $result = '';
                foreach ($dn['rdnSequence'] as $rdn) {
                    foreach ($rdn as $i => $attr) {
                        $attr = &$rdn[$i];
                        if ($attr['value'] instanceof BaseString && $attr['value']->isConvertable()) {
                            try {
                                $attr['value'] = $attr['value']->toUTF8String();
                                $attr['value']->value = strtolower((string) preg_replace('/\s+/', ' ', $attr['value']->value));
                            } catch (CharacterConversionException) {}
                        } elseif (is_array($attr['value']) || $attr['value'] instanceof Constructed) {
                            if ($attr['type'] == 'id-at-postalAddress') {
                                foreach ($attr['value'] as $key=>$val) {
                                    $val = &$attr['value'][$key];
                                    if ($val instanceof Choice && !isset($val['utf8String']) && $val->value instanceof BaseString && $val->value->isConvertable()) {
                                        $val['utf8String'] = $val->value->toUTF8String();
                                    }
                                    if ($val instanceof BaseString && $val->isConvertable()) {
                                        $val = $val->toUTF8String();
                                    }
                                    unset($val);
                                }
                            }
                            self::encodeDNS($attr['type'], $attr['value']);
                        }
                    }
                    $result .= ASN1::encodeDER($rdn, Maps\RelativeDistinguishedName::MAP);
                }
                return $result;
            case self::DN_HASH:
                $dn = self::formatDN($dn, self::DN_CANON);
                $hash = new Hash('sha1');
                $hash = $hash->hash($dn);
                $hash = unpack('Vhash', $hash)['hash'];
                return strtolower(Strings::bin2hex(pack('N', $hash)));
        }

        // Default is to return a string.
        $start = true;
        $output = '';

        $result = [];

        foreach ($dn['rdnSequence'] as $field) {
            $prop = (string) $field[0]['type'];
            $value = $field[0]['value'];

            $desc = match ($prop) {
                'id-at-countryName' => 'C',
                'id-at-stateOrProvinceName' => 'ST',
                'id-at-organizationName' => 'O',
                'id-at-organizationalUnitName' => 'OU',
                'id-at-commonName' => 'CN',
                'id-at-localityName' => 'L',
                'id-at-surname' => 'SN',
                'id-at-givenName' => 'GN',
                'id-at-uniqueIdentifier' => 'x500UniqueIdentifier',
                'jurisdictionLocalityName' => 'jurisdictionL',
                'jurisdictionOfIncorporationStateOrProvinceName' => 'jurisdictionST',
                'jurisdictionOfIncorporationCountryName' => 'jurisdictionC',
                'id-domainComponent' => 'DC',
                default => preg_replace('#.+-([^-]+)$#', '$1', $prop)
            };

            if (!$start) {
                $output .= ', ';
            }
            if (is_array($value)) {
                self::encodeDNS($prop, $value);
                if (is_array($value)) {
                    // maybe we should create an UnableToMapException ?
                    throw new RuntimeException("An unmappable array was encountered for $prop");
                }
            }
            $isConstructed = false;
            if ($value instanceof Constructed || $value instanceof Element) {
                $isConstructed = true;
                $value = '#' . strtoupper(bin2hex("$value"));
            }
            if ($value instanceof BaseString && $value->isConvertable()) {
                try {
                    $value = (string) $value->toUTF8String();
                } catch (CharacterConversionException) {}
            }

            $result[$desc] = isset($result[$desc]) ?
                array_merge((array) $result[$desc], [$value]) :
                $value;
            // replace \ with \\ and " with \"
            $value = str_replace(['\\', '"'], ['\\\\', '\"'], "$value");
            // replace non printable ascii
            $callback = fn ($x): string => '\\' . strtoupper(bin2hex((string) $x[0]));
            $value = preg_replace_callback('#[^\x20-\x7E]#', $callback, $value);
            switch (true) {
                // if there are spaces on either end or a comma in the middle then encapsulate with double quotes
                case preg_match('#^ +| +$|,#', (string) $value):
                case preg_match('/^#./', (string) $value) && !$isConstructed:
                    $value = '"' . $value . '"';
            }
            $output .= $desc . ' = ' . $value;
            $start = false;
        }

        return $format == self::DN_OPENSSL ? $result : $output;
    }

    /**
     * @return BaseType[]
     */
    private static function retrieveDNProps(array|Choice $dn, string $propName): array
    {
        $propName = self::translateDNProp($propName);
        $dn = $dn['rdnSequence'];
        $result = [];
        for ($i = 0; $i < count($dn); $i++) {
            if ($dn[$i][0]['type'] == $propName) {
                $v = $dn[$i][0]['value'];
                if (is_string($v)) {
                    $v = new UTF8String($v);
                } elseif (is_array($v)) {
                    self::encodeDNS($propName, $v);
                }
                $result[] = $v;
            }
        }

        return $result;
    }
}