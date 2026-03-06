<?php

namespace Drupal\webform_identity_login\Plugin\WebformHandler;

use Drupal\webform\Plugin\WebformHandlerBase;
use Drupal\webform\WebformSubmissionInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Component\Utility\Crypt;
use Drupal\webform_identity_login\Utils\HmacUtils;


use Civi\Api4\UFMatch;
use Civi\Api4\Contact;

/**
 * Identity login handler.
 *
 * @WebformHandler(
 *   id = "identity_login_handler",
 *   label = @Translation("Identity login handler"),
 *   category = @Translation("Custom"),
 *   description = @Translation("Authenticates user and attaches submission."),
 *   cardinality = \Drupal\webform\Plugin\WebformHandlerInterface::CARDINALITY_SINGLE,
 *   results = \Drupal\webform\Plugin\WebformHandlerInterface::RESULTS_PROCESSED,
 * )
 */
class IdentityLoginHandler extends WebformHandlerBase {

  /**
   * Whether the user has been connected during validation.
   *
   * @var bool
   */
  protected $hasBeenConnected = FALSE;

  /**
   * Whether the user is currently connected.
   *
   * @var bool
   */
  protected $userConnected = FALSE;

  /**
   * The ID of the originally connected user before switching.
   *
   * @var int|null
   */
  protected $connectedUserId = NULL;

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return parent::defaultConfiguration() + [
      'anonymous_submission' => FALSE,
      'debug' => FALSE,
      'switch_user' => FALSE,
    ];
  }

  /**
   * Returns whether debug traces are enabled.
   */
  protected function isDebugEnabled() {
    return !empty($this->configuration['debug']);
  }

  /**
   * Logs a debug trace when debug mode is enabled.
   */
  protected function logDebug($message, array $context = []) {
    if ($this->isDebugEnabled()) {
      \Drupal::logger('webform_identity_login')->debug($message, $context);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state, WebformSubmissionInterface $webform_submission) {

    $current_page = $webform_submission->getCurrentPage();
    $first_page = array_key_first($webform_submission->getWebform()->getPages());

    $this->logDebug('validateForm context - current_page: @current_page, first_page: @first_page, uid: @uid', [
      '@current_page' => $current_page ?? 'NULL',
      '@first_page' => $first_page ?? 'NULL',
      '@uid' => \Drupal::currentUser()->id(),
    ]);

    if ($current_page !== $first_page) {
      $this->logDebug('Not on first page, skipping validation');
      return parent::validateForm($form, $form_state, $webform_submission);
    }

    $request = \Drupal::request();
    $route_name = \Drupal::routeMatch()->getRouteName();

    if (str_starts_with($route_name, 'entity.webform_submission')) {
      // On est en admin edit.
      $this->logDebug('In admin edit route @route, skipping validation', ['@route' => $route_name]);
      return parent::validateForm($form, $form_state, $webform_submission);
    }

    $token = $request->query->get('token');
    // Si requete avec token, on passe la main a webform.
    if ($token) {
      $this->logDebug('Token found in request, skipping validation');
      return parent::validateForm($form, $form_state, $webform_submission);
    }

    // Récupérer les valeurs ET l'élément composite pour avoir accès à #secret_key.
    $elements = $webform_submission->getWebform()->getElementsInitializedAndFlattened();
    $values = [];
    $composite_element = NULL;

    foreach ($elements as $key => $element) {
      if (($element['#type'] ?? NULL) === 'identity_login_composite') {
        $values = $form_state->getValue($key);
        $composite_element = $element;
        break;
      }
    }

    if (!$composite_element) {
      $this->logDebug('No identity_login_composite element found in webform @webform', [
        '@webform' => $webform_submission->getWebform()->id(),
      ]);
    }

    $civicrm_id = $values['cid'] ?? NULL;
    $token      = $values['idtoken'] ?? NULL;
    $email      = $values['email'] ?? NULL;

    $this->logDebug('Validation started - CiviCRM ID: @id, Email: @email', [
      '@id'    => $civicrm_id,
      '@email' => $email,
    ]);

    $this->userConnected = FALSE;
    $this->hasBeenConnected = FALSE;
    $this->connectedUserId = NULL;

    if (!$civicrm_id || !$token || !$email) {
      $this->logDebug('Missing cid, token or email');
    }

    $this->logDebug('Composite values received: @values', [
      '@values' => json_encode($values),
    ]);

    // Récupérer le secret_key depuis l'élément decoded (pour avoir les props custom).
    $decoded_elements = $webform_submission->getWebform()->getElementsDecodedAndFlattened();
    $secret_key = NULL;
    foreach ($decoded_elements as $key => $element) {
      if (($element['#type'] ?? NULL) === 'identity_login_composite') {
        $secret_key = $element['#secret_key'] ?? NULL;
        break;
      }
    }

    $this->logDebug('Secret key configured: @configured', [
      '@configured' => empty($secret_key) ? 'NO' : 'YES',
    ]);
    if (empty($secret_key)) {
      $this->logDebug('No secret_key configured on identity_login_composite element');
    }
    // Secret key trouvé, on peut vérifier le token.
    else {
      // Vérifier le HMAC.
      $expected = HmacUtils::computeHmac($civicrm_id ?? 'Non trouve', $values['first_name'] ?? '', $values['last_name'] ?? '', $values['email'] ?? '', $secret_key);
      if (!hash_equals($expected, $token)) {
        $this->logDebug('HMAC verification failed for cid @cid, Email: @email, first_name: @first, last_name: @last, token: @token, expected: @expected', [
          '@cid' => ($civicrm_id ?? 'Non trouve'),
          '@email' => ($values['email'] ?? 'Non trouve'),
          '@first' => ($values['first_name'] ?? 'Non trouve'),
          '@last' => ($values['last_name'] ?? 'Non trouve'),
          '@token' => ($token ?? 'Non trouve'),
          '@expected' => ($expected ?? 'Non trouve'),
        ]);
      }
      // HMAC valide, on peut continuer le processus de login.
      else {
        $this->logDebug('HMAC verification successful for cid @cid, Email: @email, first_name: @first, last_name: @last', [
          '@cid' => ($civicrm_id ?? 'Non trouve'),
          '@email' => ($values['email'] ?? 'Non trouve'),
          '@first' => ($values['first_name'] ?? 'Non trouve'),
          '@last' => ($values['last_name'] ?? 'Non trouve'),
        ]);

        $this->logDebug('Initializing CiviCRM');
        \Drupal::service('civicrm')->initialize();

        $contacts = Contact::get(FALSE)
          ->addSelect('id', 'first_name', 'last_name', 'email_primary.email')
          ->addWhere('id', '=', $civicrm_id)
          ->addWhere('email_primary.email', '=', $email)
          ->setLimit(1)
          ->addChain('drupal', UFMatch::get(TRUE)
            ->addSelect('uf_id', 'id', 'uf_name')
            ->addWhere('contact_id', '=', '$id')
        )
          ->execute();

        $this->logDebug('CiviCRM query executed for cid @cid, matches: @count', [
          '@cid' => $civicrm_id,
          '@count' => $contacts->count(),
        ]);

        if ($contacts->count() === 0) {
          $this->logDebug('Contact not found in CiviCRM - ID: @id, Email: @email', [
            '@id'    => $civicrm_id,
            '@email' => $email,
          ]);

          // Aucun contact trouvé, on ne peut pas logger l'utilisateur.
          // On deconnecte l'utilisateur actuel pour éviter les problèmes de permissions sur les pages suivantes, qui pourraient causer des erreurs 403 ou des problèmes d'affichage.
          if (\Drupal::currentUser()->isAuthenticated()) {
            if ($this->configuration['switch_user'] ?? FALSE) {
              $this->connectedUserId = \Drupal::currentUser()->id();
              $this->userConnected = FALSE;
              $this->hasBeenConnected = FALSE;
            }
            $this->logout();
            $this->logDebug('Current user logged out due to failed identity login validation');
          }
        }
        // Contact trouvé, on peut logger l'utilisateur.
        else {
          $contact = $contacts->first();

          $this->logDebug('Contact found - ID: @id', ['@id' => $contact['id']]);

          $user = $this->getUserbyId($contact['drupal'][0]['uf_id']);
          if (!$user) {
            $this->logDebug('No Drupal user found for UF ID: @uf_id', [
              '@uf_id' => $contact['drupal'][0]['uf_id'],
            ]);
          }
          // User trouvé, on peut logger.
          else {
            $this->logDebug('User found - UID: @uid, User: @user', [
              '@uid'  => $user->id(),
              '@user' => $user->getAccountName(),
            ]);

            if ($user->id() === \Drupal::currentUser()->id()) {
              $this->logDebug('User @uid is already authenticated, no login needed', [
                '@uid' => $user->id(),
              ]);
              $this->userConnected = TRUE;
              $this->hasBeenConnected = FALSE;
            }
            else {
              if ($this->configuration['switch_user'] ?? FALSE) {
                $this->connectedUserId = \Drupal::currentUser()->id();
              }
              // Login.
              user_login_finalize($user);
              $this->userConnected = TRUE;
              $this->hasBeenConnected = TRUE;
              // Regénérer le token CSRF pour éviter les problèmes de token invalides après login.
              $form_id = $form_state->getCompleteForm()['#form_id'] ?? $form['#form_id'];
              // Calcul le token_value en le meme code que  FormBuilder::prepareForm(), pour que le token soit valide pour ce formulaire.
              $token_value = 'form_token_placeholder_' . Crypt::hashBase64($form_id);
              $new_token = \Drupal::csrfToken()->get($token_value);

              $user_input = $form_state->getUserInput();
              $user_input['form_token'] = $new_token;
              $form_state->setUserInput($user_input);
              $this->logDebug('CSRF form token regenerated after user login for form @form_id', [
                '@form_id' => $form_id,
              ]);
            }
          }
        }
      }
    }

    if ($this->userConnected) {
      $this->logDebug('User authenticated');
    }
    else {
      $this->logDebug('User anonymous after validation');

    }
    if (!isset($user)) {
      $user = \Drupal::currentUser();
    }

    // Vérifier s'il existe une soumission pour ce formulaire et cet utilisateur.
    $storage = \Drupal::entityTypeManager()->getStorage('webform_submission');
    $last_submission = NULL;
    if ($this->userConnected) {
      $last_submission = $storage->getLastSubmission($webform_submission->getWebform(), NULL, $user, ['in_draft' => NULL]);
    }
    // Recherche une soumission anonyme avec le meme email.
    elseif ($this->configuration['anonymous_submission'] ?? FALSE) {
      $this->logDebug('Searching anonymous submission with email @email', [
        '@email' => $email,
      ]);

      $connection = \Drupal::database();

      $sids = $connection->select('webform_submission_data', 'wsd')
        ->fields('wsd', ['sid'])
        ->condition('wsd.webform_id', $composite_element['#webform'])
        ->condition('wsd.name', $composite_element['#webform_key'])
        ->condition('wsd.property', 'email')
        ->condition('wsd.value', $email)
        ->orderBy('wsd.sid', 'DESC')
        ->range(0, 1)
        ->execute()
        ->fetchCol();

      if (!empty($sids)) {
        $last_submission = $storage->load(reset($sids));

        $this->logDebug('Anonymous submission @sid found and attached to user @uid', [
          '@sid' => $last_submission->id(),
          '@uid' => $user->id(),
        ]);
      }
    }
    $user_submission = $webform_submission;
    if ($last_submission) {
      $this->logDebug('Soumission existante trouvée: @sid', ['@sid' => $last_submission->id()]);
      $user_submission = $last_submission;
      // Attacher la soumission existante au form state.
      $form_state->getFormObject()->setEntity($user_submission);
    }
    else {
      $this->logDebug('Aucune soumission existante trouvée pour ce formulaire et cet utilisateur');
    }

    $pages = $user_submission->getWebform()->getPages();
    $page_keys = array_keys($pages);
    $current_page = $form_state->get('current_page') ?: $user_submission->getCurrentPage();

    if (!$current_page && !empty($page_keys)) {
      $current_page = reset($page_keys);
    }

    $next_page = NULL;
    if ($current_page && !empty($page_keys)) {
      $current_index = array_search($current_page, $page_keys, TRUE);
      if ($current_index !== FALSE && isset($page_keys[$current_index + 1])) {
        $next_page = $page_keys[$current_index + 1];
      }
    }

    if ($next_page) {
      $form_state->set('current_page', $next_page);
      $user_submission->setCurrentPage($next_page);
      $this->logDebug('Navigation updated from @current to @next for submission @sid', [
        '@current' => $current_page ?? 'NULL',
        '@next' => $next_page,
        '@sid' => $user_submission->id(),
      ]);
    }

    $this->logDebug('last_submission: sid=@s, page=@p, draft=@d, completed=@c', [
      '@s' => $user_submission->id(),
      '@p' => $user_submission->getCurrentPage(),
      '@d' => $user_submission->isDraft() ? 'YES' : 'NO',
      '@c' => $user_submission->isCompleted() ? 'YES' : 'NO',
    ]);

    if ($this->hasBeenConnected) {
      $user_submission->setOwnerId($user->id());
      $user_submission->save();
      $this->logDebug('Submission @sid ownership set to uid @uid and saved', [
        '@sid' => $user_submission->id(),
        '@uid' => $user->id(),
      ]);
    }
    elseif ($this->connectedUserId && !$this->userConnected) {
      // Si on a un utilisateur connecté avant validation, mais que la validation a échoué,
      // on attribut la soumission a l'utilisateur anonyme.
      $user_submission->setOwnerId($user->id());
      $user_submission->save();
      $this->logDebug('Submission @sid set to anonymous and saved', [
        '@sid' => $user_submission->id(),
        '@uid' => $this->connectedUserId,
      ]);
    }

    $form_state->setRebuild();
  }

  /**
   * {@inheritdoc}
   */
  public function alterForm(array &$form, FormStateInterface $form_state, WebformSubmissionInterface $webform_submission) {
    // On vérifie si l'élément 'information' existe dans la structure du formulaire.
    if (isset($form['information'])) {
      // Utiliser #access => FALSE est plus propre que unset()
      // Cela empêche l'affichage et la validation sans supprimer l'index.
      $form['information']['#access'] = FALSE;
    }

  }

  /**
   * {@inheritdoc}
   */
  public function postSave(WebformSubmissionInterface $webform_submission, $update = TRUE) {
    parent::postSave($webform_submission, $update);
    $current_page = $webform_submission->getCurrentPage();
    $last_page = array_key_last($webform_submission->getWebform()->getPages());
    $this->logDebug('postSave called for submission @sid (current_page=@current, last_page=@last)', [
      '@sid' => $webform_submission->id(),
      '@current' => $current_page ?? 'NULL',
      '@last' => $last_page ?? 'NULL',
    ]);

    if ($current_page === $last_page) {
      // Tu peux exécuter du code serveur si besoin, par ex. déconnexion.
      $current_user = \Drupal::currentUser();

      if ($current_user->isAuthenticated() && $this->hasBeenConnected) {
        // Traitement d'un formulaire soumis par un autre utilisateur.
        $this->logDebug('User @uid was connected during submission, logging out after completion', [
          '@uid' => $current_user->id(),
        ]);
        $this->logout();
        if ($this->configuration['switch_user'] ?? FALSE) {
          $this->logDebug('User switched during submission, original user @uid reconnexion', [
            '@uid' => $this->connectedUserId,
          ]);
          if ($this->connectedUserId) {
            user_login_finalize($this->getUserbyId($this->connectedUserId_id));
          }
          else {
            $this->logDebug('No original user ID found for reconnection after submission completion');
          }
        }
        else {
          $this->logDebug('User logged out after submission completion (no switch_user)');
        }
        return;
      }

      if ($current_user->isAuthenticated() && !$this->hasBeenConnected) {
        // Meme utilisateur.
        $this->logDebug('User @uid is authenticated but was not connected during submission, no logout', [
          '@uid' => $current_user->id(),
        ]);
        return;
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildConfigurationForm($form, $form_state);

    $form['debug'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Debug'),
      '#description' => $this->t('Enable additional debug traces for this handler.'),
      '#default_value' => $this->configuration['debug'] ?? FALSE,
      '#return_value' => TRUE,
    ];

    $form['anonymous_submission'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow to retrieve anonymous submission'),
      '#description' => $this->t('Allow to retrieve anonymous submission based on email match, if no authenticated submission found for the user.'),
      '#default_value' => $this->configuration['anonymous_submission'] ?? FALSE,
      '#return_value' => TRUE,
    ];

    $form['switch_user'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Switch user on submission'),
      '#description' => $this->t('If checked, the handler will switch the current user to the user found via CiviCRM match, even if there is already an authenticated user. USE WITH CAUTION as it can have security implications.'),
      '#default_value' => $this->configuration['switch_user'] ?? FALSE,
      '#return_value' => TRUE,
    ];
    return $form;
  }

  /**
   *
   */
  private function getUserbyId($uid) {
    $users = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->loadByProperties(['uid' => $uid]);
    $user = reset($users);

    return $user ?? NULL;
  }

  /**
   *
   */
  private function logout() {
    user_logout();

    // Détruire totalement la session Symfony.
    $session = \Drupal::request()->getSession();
    $session->invalidate();
  }

}
