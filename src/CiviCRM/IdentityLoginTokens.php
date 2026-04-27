<?php

namespace Drupal\webform_identity_login\CiviCRM;

use Civi\Api4\Contact;
use Civi\Token\Event\TokenRegisterEvent;
use Civi\Token\Event\TokenValueEvent;
use Civi\Token\AbstractTokenSubscriber;
use Civi\Token\TokenRow;
use Drupal\webform_identity_login\Utils\HmacUtils;

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
    $messageTokens = $e->getTokenProcessor()->getMessageTokens()[$this->entity] ?? [];

    $available = [];
    foreach ($this->getWebformConfigs() as $webform_id => $config) {
      $available[] = 'url_' . $webform_id;
    }

    return array_intersect($available, $messageTokens);
  }

  /**
   * {@inheritdoc}
   */
  public function prefetch(TokenValueEvent $e): void {
    // Pas de prefetch nécessaire, les données viennent du contexte du contact.
  }

  /**
   *
   */
  public function registerTokens(TokenRegisterEvent $e): void {
    /*  if ($e->getEntity() !== $this->entity) {
    return;
    } */

    foreach ($this->getWebformConfigs() as $webform_id => $config) {
      $e->register([
        'entity' => $this->entity,
        'field' => 'url_' . $webform_id,
        'label' => ts('Identity Login URL - %1', [1 => $webform_id]),
      ]);
    }
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

    // Récupérer les données du contact via l'API CiviCRM.
    try {
      if ($contact_id == 1) {
        // Cas d'un en envoi de test a une adresse (pas une liste)
        // visiblement le contact_id est celui de l'utilisateur admin (1) au lieu de celui du contact de test, ce qui génère une erreur car il n'existe pas de UFMatch pour ce contact.
        // recherche le contact_id a partir de l'adresse mail.
        $contact = Contact::get(FALSE)
          ->addSelect('first_name', 'last_name', 'email_primary.email', 'phone_primary.phone')
          ->addWhere('email_primary.email', '=', $row->context['mailingActionTarget']['email'] ?? '')
          ->addWhere('id', '!=', 1)
          ->execute()
          ->first();
      }
      else {

        $contact = Contact::get(FALSE)
          ->addSelect('first_name', 'last_name', 'email_primary.email', 'phone_primary.phone')
          ->addWhere('id', '=', $contact_id)
          ->execute()
          ->first();
      }
    }
    catch (\Exception $e) {
      \Civi::log()->error('IdentityLoginTokens: erreur récupération contact @cid : @msg', [
        '@cid' => $contact_id,
        '@msg' => $e->getMessage(),
      ]);
      $row->format('text/plain')->tokens('identity_login', $field, '');
      return;
    }

    $token = HmacUtils::computeHmac(
    $contact['id'] ?? '',
    $contact['first_name'] ?? '',
    $contact['last_name'] ?? '',
    $contact['email_primary.email'] ?? '',
    $secret_key
    );

    // Construire l'URL.
    // format : https://mcm65.famh.fr/form/pascuet-mai-2026-v2?idtoken=f40126d1d69c4b364fa4bb6e3e83101bbeb59119efd73884afa342237a81a7e0&cid=7689&first_name=Yohan&last_name=ARBERET&email=yohan.arberet%40sfr.fr&phone=06%2026%2068%2048%2067
    $url = $webform_url . '?' . http_build_query([
      'idtoken' => $token,
      'cid' => $contact['id'] ?? '',
      'first_name' => $contact['first_name'] ?? '',
      'last_name' => $contact['last_name'] ?? '',
      'email' => $contact['email_primary.email'] ?? '',
      'phone' => $contact['phone_primary.phone'] ?? '',
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

          // Générer l'URL du webform, sans le scheme (http/https) pour éviter que l'éditeur de mail CiviCRM n'ajoute automatiquement "http://" devant, ce qui casserait le lien si le site est en https.
          $url = preg_replace(
          '#^[a-zA-Z][a-zA-Z0-9+.-]*://#',
          '',
          $webform->toUrl('canonical', ['absolute' => TRUE])->toString()
          );

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

  /**
   *
   */
  public function getAllTokens(): array {
    $tokens = [];
    foreach ($this->getWebformConfigs() as $webform_id => $config) {
      $tokens['url_' . $webform_id] = ts('Identity Login URL - %1', [
        1 => $webform_id,
      ]);
    }
    return $tokens;
  }

}
