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
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state, WebformSubmissionInterface $webform_submission) {

    $current_page = $webform_submission->getCurrentPage();
    $first_page = array_key_first($webform_submission->getWebform()->getPages());

    $logger = \Drupal::logger('webform_identity_login');
    $logger->info('validateForm called');

    if ($current_page !== $first_page) {
      return parent::validateForm($form, $form_state, $webform_submission);
    }

    $request = \Drupal::request();
    $token = $request->query->get('token');
    // Si requete avec token, on passe la main a webform.
    if ($token) {
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
      $logger->warning('No identity_login_composite element found');
      return;
    }

    $civicrm_id = $values['cid'] ?? NULL;
    $token      = $values['idtoken'] ?? NULL;
    $email      = $values['email'] ?? NULL;

    $logger->info('Validation started - CiviCRM ID: @id, Email: @email', [
      '@id'    => $civicrm_id,
      '@email' => $email,
    ]);

    $user_connected = FALSE;
    $has_been_connected = FALSE;

    if (!$civicrm_id || !$token || !$email) {
      $logger->warning('Missing cid, token or email - skipping validation');
    }

    if (!\Drupal::currentUser()->isAuthenticated()) {
      $logger->info('User not authenticated - proceeding with identity login validation');

      // Récupérer le secret_key depuis l'élément decoded (pour avoir les props custom).
      $decoded_elements = $webform_submission->getWebform()->getElementsDecodedAndFlattened();
      $secret_key = NULL;
      foreach ($decoded_elements as $key => $element) {
        if (($element['#type'] ?? NULL) === 'identity_login_composite') {
          $secret_key = $element['#secret_key'] ?? NULL;
          break;
        }
      }

      if (empty($secret_key)) {
        $logger->error('No secret_key configured on identity_login_composite element');
      }
      // Secret key trouvé, on peut vérifier le token.
      else {
        // Vérifier le HMAC.
        $expected = HmacUtils::computeHmac($civicrm_id ?? 'Non trouve', $values['first_name'] ?? '', $values['last_name'] ?? '', $values['email'] ?? '', $secret_key);
        if (!hash_equals($expected, $token)) {
          $logger->warning('HMAC verification failed for cid @cid, Email: @email, first_name: @first, last_name: @last', [
            '@cid' => ($civicrm_id ?? 'Non trouve'),
            '@email' => ($values['email'] ?? 'Non trouve'),
            '@first' => ($values['first_name'] ?? 'Non trouve'),
            '@last' => ($values['last_name'] ?? 'Non trouve'),
          ]);
        }
        // HMAC valide, on peut continuer le processus de login.
        else {
          $logger->info('HMAC verification successful for cid @cid, Email: @email, first_name: @first, last_name: @last', [
            '@cid' => ($civicrm_id ?? 'Non trouve'),
            '@email' => ($values['email'] ?? 'Non trouve'),
            '@first' => ($values['first_name'] ?? 'Non trouve'),
            '@last' => ($values['last_name'] ?? 'Non trouve'),
          ]);

          $logger->info('Initializing CiviCRM');
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

          if ($contacts->count() === 0) {
            $logger->error('Contact not found in CiviCRM - ID: @id, Email: @email', [
              '@id'    => $civicrm_id,
              '@email' => $email,
            ]);
          }
          // Contact trouvé, on peut logger l'utilisateur.
          else {
            $contact = $contacts->first();

            $logger->info('Contact found - ID: @id', ['@id' => $contact['id']]);

            // Plus besoin du hash natif CiviCRM, le HMAC suffit.
            $users = \Drupal::entityTypeManager()
              ->getStorage('user')
              ->loadByProperties(['uid' => $contact['drupal'][0]['uf_id']]);

            if (!$user = reset($users)) {
              $logger->error('No Drupal user found for UF ID: @uf_id', [
                '@uf_id' => $contact['drupal'][0]['uf_id'],
              ]);
            }
            // User trouvé, on peut logger.
            else {
              $logger->info('User found - UID: @uid, User: @user', [
                '@uid'  => $user->id(),
                '@user' => $user->getAccountName(),
              ]);

              // Login.
              user_login_finalize($user);
              $user_connected = TRUE;
              $has_been_connected = TRUE;
              // Regénérer le token CSRF pour éviter les problèmes de token invalides après login.
              $form_id = $form_state->getCompleteForm()['#form_id'] ?? $form['#form_id'];
              // Calcul le token_value en le meme code que  FormBuilder::prepareForm(), pour que le token soit valide pour ce formulaire.
              $token_value = 'form_token_placeholder_' . Crypt::hashBase64($form_id);
              $new_token = \Drupal::csrfToken()->get($token_value);

              $user_input = $form_state->getUserInput();
              $user_input['form_token'] = $new_token;
              $form_state->setUserInput($user_input);

            }
          }
        }
      }
    }
    else {
      $logger->info('User already authenticated - skipping identity login validation');
      $user_connected = TRUE;
    }

    if ($user_connected) {
      $logger->info('User authenticated');
    }
    else {
      $logger->warning('User anonymous after validation');

    }
    if (!isset($user)) {
      $user = \Drupal::currentUser();
    }

    // Vérifier s'il existe une soumission pour ce formulaire et cet utilisateur.
    $storage = \Drupal::entityTypeManager()->getStorage('webform_submission');
    $last_submission = NULL;
    if ($user_connected) {
      $last_submission = $storage->getLastSubmission($webform_submission->getWebform(), NULL, $user, ['in_draft' => NULL]);
    }
    // Recherche une soumission anonyme avec le meme email.
    else {
      $logger->info('Searching anonymous submission with email @email', [
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

        $logger->info('Anonymous submission @sid found and attached to user @uid', [
          '@sid' => $last_submission->id(),
          '@uid' => $user->id(),
        ]);
      }
    }
    $user_submission = $webform_submission;
    if ($last_submission) {
      $logger->info('Soumission existante trouvée: @sid', ['@sid' => $last_submission->id()]);
      $user_submission = $last_submission;
      // Attacher la soumission existante au form state.
      $form_state->getFormObject()->setEntity($user_submission);
    }
    $user_submission->setData($user_submission->getData() + [
      'has_been_connected' => $has_been_connected,
    ]);
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
    }

    $logger->debug('last_submission: sid=@s, page=@p, draft=@d, completed=@c', [
      '@s' => $user_submission->id(),
      '@p' => $user_submission->getCurrentPage(),
      '@d' => $user_submission->isDraft() ? 'YES' : 'NO',
      '@c' => $user_submission->isCompleted() ? 'YES' : 'NO',
    ]);

    if ($has_been_connected) {
      $user_submission->setOwnerId($user->id());
      $user_submission->save();
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
   *
   */
  public function postSave(WebformSubmissionInterface $webform_submission, $update = TRUE) {
    parent::postSave($webform_submission, $update);
    $current_page = $webform_submission->getCurrentPage();
    $last_page = array_key_last($webform_submission->getWebform()->getPages());

    if ($current_page === $last_page) {
      // Tu peux exécuter du code serveur si besoin, par ex. déconnexion.
      $current_user = \Drupal::currentUser();
      $has_been_connected = $webform_submission->getData()['has_been_connected'] ?? FALSE;
      if ($current_user->isAuthenticated() && $has_been_connected) {
        // Déconnexion Drupal.
        user_logout();

        // 2️⃣ Détruire totalement la session Symfony
        $session = \Drupal::request()->getSession();
        $session->invalidate();

      }
    }
  }

}
