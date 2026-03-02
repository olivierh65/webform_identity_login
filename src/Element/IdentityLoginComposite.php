<?php

namespace Drupal\webform_identity_login\Element;

use Drupal\webform\Element\WebformCompositeBase;

/**
 * @FormElement("identity_login_composite")
 */
class IdentityLoginComposite extends WebformCompositeBase {

  /**
   *
   */
  public function getInfo() {
    $info = parent::getInfo();
    $info['#theme'] = 'identity_login_composite';
    $info['#theme_wrappers'] = ['form_element'];
    // Ajouter à la liste existante, ne pas remplacer.
    $info['#pre_render'][] = [static::class, 'preRenderIdentityLogin'];
    return $info;
  }

  /**
   *
   */
  public static function preRenderIdentityLogin(array $element) {

    $element['#attached']['library'][] = 'webform_identity_login/identity-login';

    return $element;
  }

  /**
   *
   * @return array
   */
  public static function getCompositeElements(array $element) {
    $elements = [
      'first_name' => [
        '#type' => 'textfield',
        '#title' => 'Prénom',
        '#title_display' => 'before',
        '#maxlength' => 32,
        '#size' => 32,
        '#required' => FALSE,
      ],
      'last_name' => [
        '#type' => 'textfield',
        '#title' => 'Nom',
        '#title_display' => 'before',
        '#maxlength' => 64,
        '#size' => 64,
        '#required' => FALSE,
      ],
      'phone' => [
        '#type' => 'textfield',
        '#title' => 'Téléphone',
        '#title_display' => 'before',
        '#maxlength' => 20,
        '#size' => 20,
        '#required' => FALSE,
      ],
      'email' => [
        '#type' => 'email',
        '#title' => 'Email',
        '#title_display' => 'before',
        '#maxlength' => 254,
        '#size' => 64,
        '#required' => FALSE,
      ],
      'street' => [
        '#type' => 'textfield',
        '#title' => 'Rue',
        '#title_display' => 'before',
        '#maxlength' => 128,
        '#size' => 64,
        '#required' => FALSE,
      ],
      'street2' => [
        '#type' => 'textfield',
        '#title' => 'Complément d\'adresse',
        '#title_display' => 'before',
        '#maxlength' => 128,
        '#size' => 64,
        '#required' => FALSE,
      ],
      'postal_code' => [
        '#type' => 'textfield',
        '#title' => 'Code postal',
        '#title_display' => 'before',
        '#maxlength' => 5,
        '#size' => 6,
        '#required' => FALSE,
      ],
      'city' => [
        '#type' => 'textfield',
        '#title' => 'Ville',
        '#title_display' => 'before',
        '#maxlength' => 64,
        '#size' => 32,
        '#required' => FALSE,
      ],
      'cid' => [
        '#type' => 'hidden',
        '#title' => t('CiviCRM ID'),
        '#required' => FALSE,
      ],
      'hash' => [
        '#type' => 'hidden',
        '#title' => t('Security hash'),
        '#required' => FALSE,
      ],
      'fid' => [
        '#type' => 'hidden',
        '#title' => t('Form ID'),
        '#required' => FALSE,
      ],
      'idtoken' => [
        '#type' => 'hidden',
        '#title' => t('Form security hash'),
        '#required' => FALSE,
      ],
    ];
    return $elements;
  }

}
