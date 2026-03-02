<?php

namespace Drupal\webform_identity_login\CiviCRM;

use Civi\Token\Event\TokenValueEvent;
use Civi\Token\AbstractTokenSubscriber;
use Civi\Token\TokenRow;

/**
 * Fournit le token {identity_login.url} pour les mailings CiviCRM.
 *
 * Usage dans un mailing CiviCRM :
 *   {identity_login.url_MON_WEBFORM_ID}
 *
 * Le secret_key est configuré dans chaque webform element "identity_login_composite".
 */
class IdentityLoginTokens extends AbstractTokenSubscriber {

  /**
   * {@inheritdoc}
   */
  public function __construct() {
    parent::__construct('identity_login', []);
  }

  /**
   * {@inheritdoc}
   *
   * Déclare dynamiquement un token par webform contenant un élément
   * identity_login_composite avec une secret_key configurée.
   */
  public function getActiveTokens(TokenValueEvent $e): array {
    $tokens = [];
    foreach ($this->getWebformConfigs() as $webform_id => $config) {
      $tokens[] = 'url_' . $webform_id;
    }
    return $tokens;
  }

  /**
   * {@inheritdoc}
   */
  public function prefetch(TokenValueEvent $e): void {
    // Pas de prefetch nécessaire, les données viennent du contexte du contact.
  }

  /**
   * {@inheritdoc}
   */
  public function evaluateToken(TokenRow $row, $entity, $field, $prefetch = NULL): void {
    // $field = 'url_MON_WEBFORM_ID'
    if (!str_starts_with($field, 'url_')) {
      return;
    }

    $webform_id = substr($field, 4);
    $configs = $this->getWebformConfigs();

    if (!isset($configs[$webform_id])) {
      $row->format('text/plain')->tokens('identity_login', $field, '');
      return;
    }

    $config = $configs[$webform_id];
    $secret_key = $config['secret_key'];
    $webform_url = $config['url'];

    // Récupérer le contact_id depuis le contexte du token.
    $contact_id = $row->context['contactId'] ?? NULL;

    if (!$contact_id || !$secret_key) {
      $row->format('text/plain')->tokens('identity_login', $field, '');
      return;
    }

    // Générer le HMAC.
    $token = hash_hmac('sha256', (string) $contact_id, $secret_key);

    // Construire l'URL.
    $url = $webform_url . '?' . http_build_query([
      'idtoken' => $token,
    ]);

    $row->format('text/html')->tokens('identity_login', $field, $url);
  }

  /**
   * Retourne la liste des webforms avec un élément identity_login_composite
   * configuré avec une secret_key.
   *
   * @return array
   *   Tableau indexé par webform_id :
   *   [
   *     'my_webform' => [
   *       'secret_key' => 'xxx',
   *       'url'        => 'https://monsite.fr/form/my-webform',
   *     ],
   *   ]
   */
  protected function getWebformConfigs(): array {
    $configs = [];

    try {
      $webform_storage = \Drupal::entityTypeManager()->getStorage('webform');
      $webforms = $webform_storage->loadMultiple();

      foreach ($webforms as $webform) {
        $elements = $webform->getElementsDecodedAndFlattened();
        foreach ($elements as $element) {
          if (($element['#type'] ?? NULL) !== 'identity_login_composite') {
            continue;
          }

          $secret_key = $element['#secret_key'] ?? '';
          if (empty($secret_key)) {
            continue;
          }

          // Générer l'URL absolue du webform.
          $url = \Drupal::request()->getSchemeAndHttpHost()
            . $webform->toUrl('canonical')->toString();

          $configs[$webform->id()] = [
            'secret_key' => $secret_key,
            'url'        => $url,
          ];

          // Un seul élément composite par webform.
          break;
        }
      }
    }
    catch (\Exception $e) {
      \Drupal::logger('webform_identity_login')->error(
        'Erreur lors de la récupération des configs webform : @msg',
        ['@msg' => $e->getMessage()]
      );
    }

    return $configs;
  }

}
