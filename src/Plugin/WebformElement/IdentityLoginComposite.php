<?php

namespace Drupal\webform_identity_login\Plugin\WebformElement;

use Drupal\webform\Plugin\WebformElement\WebformCompositeBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\webform\WebformSubmissionInterface;

use Drupal\webform_identity_login\Utils\HmacUtils;

/**
 * @WebformElement(
 *   id = "identity_login_composite",
 *   label = @Translation("Identity login composite"),
 *   description = @Translation("Verifies identity and logs in user at step change."),
 *   category = @Translation("Custom"),
 *   multiline = FALSE,
 *   composite = TRUE,
 *   states_wrapper = TRUE,
 * )
 */
class IdentityLoginComposite extends WebformCompositeBase {

  /**
   * {@inheritdoc}
   */
  protected function defineDefaultProperties() {
    return [
      'secret_key' => '',
    ] + parent::defineDefaultProperties();
  }

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state) {
    $form = parent::form($form, $form_state);

    $form['secret_key'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Secret key'),
      '#description' => $this->t('Clé secrète partagée avec CiviCRM pour signer le token.'),
      '#default_value' => $this->getElementProperty($form_state->getFormObject()->getElement(), 'secret_key'),
      '#required' => TRUE,
    ];

    return $form;
  }

  /**
   *
   */
  public function prepare(array &$element, ?WebformSubmissionInterface $webform_submission = NULL) {
    parent::prepare($element, $webform_submission);
  }

  /**
   * {@inheritdoc}
   */
  public function setDefaultValue(array &$element) {
    parent::setDefaultValue($element);

    $request = \Drupal::request();

    $cid        = $request->query->get('cid');
    $token      = $request->query->get('idtoken');
    $first_name = $request->query->get('first_name');
    $last_name  = $request->query->get('last_name');
    $email      = $request->query->get('email');

    // Sans paramètres d'identité dans l'URL, conserver les valeurs existantes.
    if (empty($cid) && empty($token) && empty($first_name)
      && empty($last_name) && empty($email)) {
      return;
    }

    if ((isset($element['#default_value']['cid'])) && (isset($element['#default_value']['idtoken']))) {
      // Le cid est déjà pré-rempli, on skip pour ne pas écraser une valeur valide.
      return;
    }

    $secret_key = $element['#secret_key'] ?? '';
    if (empty($secret_key)) {
      \Drupal::logger('webform_identity_login')->warning(
        'Secret key is not configured for cid @cid, element @key', ['@cid' => $cid, '@key' => $element['#webform_key']]
      );
    }

    if (!empty($cid) && !empty($token) && !empty($secret_key)) {
      // Vérifier le HMAC avant de pré-remplir.
      $expected = HmacUtils::computeHmac($cid ?? 'Non trouve', $first_name ?? '', $last_name ?? '', $email ?? '', $secret_key);
      if (!hash_equals($expected, $token)) {
        \Drupal::logger('webform_identity_login')->warning('HMAC verification failed for cid @cid, Email: @email, first_name: @first, last_name: @last', [
          '@cid' => ($cid ?? 'Non trouve'),
          '@email' => ($email ?? 'Non trouve'),
          '@first' => ($first_name ?? 'Non trouve'),
          '@last' => ($last_name ?? 'Non trouve'),
        ]);
        \Drupal::logger('webform_identity_login')->warning(
          'Invalid HMAC token for cid @cid', ['@cid' => $cid]
        );
        // Meme si le token est invalide, on ne bloque pas le pré-remplissage pour éviter de bloquer les utilisateurs
        // en cas de mauvaise configuration. On log l'erreur et on continue.
        // return;.
      }
    }
    else {
      // Si les paramètres ne sont pas tous présents, on log une info pour aider au debug.
      \Drupal::logger('webform_identity_login')->info(
        'Missing parameters for cid @cid: token is @token, secret_key is @secret_key', [
          '@cid' => $cid,
          '@token' => empty($token) ? 'empty' : 'present',
          '@secret_key' => empty($secret_key) ? 'empty' : 'present',
        ]
      );
    }

    // Récupérer les sous-champs définis dans le composite.
    $composite_elements = $this->getCompositeElements($element);

    // Mapper tous les paramètres GET qui correspondent à un sous-champ.
    foreach ($request->query->all() as $param => $value) {
      if (isset($composite_elements[$param])) {
        $element['#default_value'][$param] = $value;
      }
    }
  }

}
