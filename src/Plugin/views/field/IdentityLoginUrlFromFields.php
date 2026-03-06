<?php

namespace Drupal\webform_identity_login\Plugin\views\field;

use Drupal\Core\Form\FormStateInterface;
use Drupal\views\Plugin\views\field\FieldPluginBase;
use Drupal\views\ResultRow;
use Drupal\Core\Url;
use Drupal\webform_identity_login\Utils\HmacUtils;

/**
 * Provides identity login URL built from configurable view fields.
 *
 * @ViewsField("identity_login_url_from_fields")
 */
class IdentityLoginUrlFromFields extends FieldPluginBase {

  /**
   *
   */
  public function query() {
    // Champ calculé, pas de colonne SQL.
  }

  /**
   *
   */
  protected function defineOptions() {
    $options = parent::defineOptions();

    $options['cid_field']       = ['default' => ''];
    $options['firstname_field'] = ['default' => ''];
    $options['lastname_field']  = ['default' => ''];
    $options['email_field']     = ['default' => ''];
    $options['phone_field']     = ['default' => ''];
    $options['webform_id']      = ['default' => ''];

    return $options;
  }

  /**
   *
   */
  public function buildOptionsForm(&$form, FormStateInterface $form_state) {
    parent::buildOptionsForm($form, $form_state);

    $field_options = $this->getViewFieldOptions();

    $form['cid_field'] = [
      '#type' => 'select',
      '#title' => $this->t('CID field'),
      '#options' => $field_options,
      '#default_value' => $this->options['cid_field'],
      '#empty_option' => $this->t('- Select a field -'),
    ];

    $form['firstname_field'] = [
      '#type' => 'select',
      '#title' => $this->t('Firstname field'),
      '#options' => $field_options,
      '#default_value' => $this->options['firstname_field'],
      '#empty_option' => $this->t('- Select a field -'),
    ];

    $form['lastname_field'] = [
      '#type' => 'select',
      '#title' => $this->t('Lastname field'),
      '#options' => $field_options,
      '#default_value' => $this->options['lastname_field'],
      '#empty_option' => $this->t('- Select a field -'),
    ];

    $form['email_field'] = [
      '#type' => 'select',
      '#title' => $this->t('Email field'),
      '#options' => $field_options,
      '#default_value' => $this->options['email_field'],
      '#empty_option' => $this->t('- Select a field -'),
    ];

    $form['phone_field'] = [
      '#type' => 'select',
      '#title' => $this->t('Phone field'),
      '#options' => $field_options,
      '#default_value' => $this->options['phone_field'],
      '#empty_option' => $this->t('- Select a field -'),
    ];

    $form['webform_id'] = [
      '#type' => 'select',
      '#title' => $this->t('Webform'),
      '#options' => $this->getWebformOptions(),
      '#default_value' => $this->options['webform_id'],
      '#empty_option' => $this->t('- Select a webform -'),
    ];

  }

  /**
   *
   */
  public function render(ResultRow $values) {
    // Récupérer les valeurs depuis les autres champs de la vue.
    $cid        = $this->getFieldValue($values, 'cid_field');
    $firstname  = $this->getFieldValue($values, 'firstname_field');
    $lastname   = $this->getFieldValue($values, 'lastname_field');
    $email      = $this->getFieldValue($values, 'email_field');
    $phone = $this->getFieldValue($values, 'phone_field');
    $webform_id = $this->options['webform_id'];
    $secret_key = $this->getSecretKeyForWebform($webform_id);

    if (!$cid || !$webform_id || !$secret_key) {
      return '';
    }

    $token = HmacUtils::computeHmac($cid, $firstname, $lastname, $email, $secret_key);

    $url = Url::fromRoute('entity.webform.canonical', [
      'webform' => $webform_id,
    ], [
      'query' => [
        'idtoken' => $token,
        'cid' => $cid,
        'first_name' => $firstname,
        'last_name' => $lastname,
        'email' => $email,
        'phone' => $phone,

      ],
      'absolute' => TRUE,
    ]);

    return $url->toString();
  }

  /**
   * Retrieves the rendered value of another field in the current row.
   */
  protected function getFieldValue(ResultRow $values, string $option_key): string {
    $field_id = $this->options[$option_key] ?? '';

    if (!$field_id) {
      return '';
    }

    $fields = $this->displayHandler->getHandlers('field');

    if (!isset($fields[$field_id])) {
      return '';
    }

    // Utilise la valeur brute plutôt que le rendu HTML.
    $value = $fields[$field_id]->getValue($values);

    return (string) ($value ?? '');
  }

  /**
   * Gets all available webforms as select options.
   */
  protected function getWebformOptions(): array {
    $options = [];
    $webforms = \Drupal::entityTypeManager()
      ->getStorage('webform')
      ->loadMultiple();

    foreach ($webforms as $id => $webform) {
      $options[$id] = $webform->label() . ' (' . $id . ')';
    }

    return $options;
  }

  /**
   * Gets available field options from the current view display.
   */
  protected function getViewFieldOptions(): array {
    $options = [];

    if (!isset($this->displayHandler)) {
      return $options;
    }

    $fields = $this->displayHandler->getHandlers('field');

    foreach ($fields as $field_id => $field) {
      $label = $field->adminLabel() ?: ($field->definition['title'] ?? $field_id);
      $suffix = !empty($field->options['exclude']) ? ' (hidden)' : '';
      $options[$field_id] = $label . ' (' . $field_id . ')' . $suffix;
    }

    return $options;
  }

  /**
   *
   */
  private function getSecretKeyForWebform($webform_id) {
    if (!$webform_id) {
      return '';
    }

    $webform = \Drupal::entityTypeManager()
      ->getStorage('webform')
      ->load($webform_id);

    if (!$webform) {
      return '';
    }

    $elements = $webform->getElementsDecodedAndFlattened();

    foreach ($elements as $element) {
      if (($element['#type'] ?? NULL) === 'identity_login_composite') {
        return $element['#secret_key'] ?? '';
      }
    }

    return '';
  }

}
