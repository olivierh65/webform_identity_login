<?php

namespace Drupal\webform_identity_login\Utils;

/**
 *
 */
class HmacUtils {

  /**
   *
   */
  public static function normalizeForHmac(string $value): string {
    // Remplacer les caractères accentués.
    $value = transliterator_transliterate('Any-Latin; Latin-ASCII', $value);
    // Mettre en minuscule.
    $value = strtolower($value);
    // Supprimer espaces, tirets, apostrophes, points.
    $value = preg_replace('/[\s\-\'\.]+/', '', $value);

    return $value;
  }

  /**
   *
   */
  public static function computeHmac(string $cid, string $first_name, string $last_name, string $email, string $secret_key): string {
    $hmac_data = implode('|', [
      $cid,
      self::normalizeForHmac($first_name),
      self::normalizeForHmac($last_name),
      self::normalizeForHmac($email),
    ]);
    return hash_hmac('sha256', $hmac_data, $secret_key);
  }

}
