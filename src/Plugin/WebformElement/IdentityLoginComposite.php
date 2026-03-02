<?php

namespace Drupal\webform_identity_login\Plugin\WebformElement;

use Drupal\webform\Plugin\WebformElement\WebformCompositeBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * @WebformElement(
 *   id = "identity_login_composite",
 *   label = @Translation("Identity login composite"),
 *   description = @Translation("Verifies identity and logs in user at step change."),
 *   category = @Translation("Custom"),
 *   multiline = FALSE,
 *   composite = TRUE,
 *   states_wrapper = FALSE,
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
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function setDefaultValue(array &$element) {
    parent::setDefaultValue($element);

    $request = \Drupal::request();

    // Si ce n'est pas une requête GET initiale, on skip.
    if (!$request->isMethod('GET')) {
      return;
    }

    $cid   = $request->query->get('cid');
    $token = $request->query->get('idtoken');

    if (!$cid || !$token) {
      return;
    }

    $secret_key = $element['#secret_key'] ?? '';
    if (empty($secret_key)) {
      return;
    }

    // Vérifier le HMAC avant de pré-remplir.
    $expected = hash_hmac('sha256', (string) $cid, $secret_key);
    if (!hash_equals($expected, $token)) {
      \Drupal::logger('webform_identity_login')->warning(
      'Token HMAC invalide pour cid @cid', ['@cid' => $cid]
      );
      // Meme si le token est invalide, on ne bloque pas le pré-remplissage pour éviter de bloquer les utilisateurs
      // en cas de mauvaise configuration. On log l'erreur et on continue.
      // return;.
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
