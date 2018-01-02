<?php
/**
 * @package    xws_autouserlogin
 *
 * @author     tonypartridge <your@email.com>
 * @copyright  A copyright
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 * @link       http://your.url.com
 */

use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Database\DatabaseDriver;

defined('_JEXEC') or die;

/**
 * Xws_autouserlogin plugin.
 *
 * @package  xws_autouserlogin
 * @since    1.0
 */
class plgSystemXws_autouserlogin extends CMSPlugin
{
	/**
	 * Application object
	 *
	 * @var    CMSApplication
	 * @since  1.0
	 */
	protected $app;

	/**
	 * Database object
	 *
	 * @var    DatabaseDriver
	 * @since  1.0
	 */
	protected $db;

	/**
	 * Affects constructor behavior. If true, language files will be loaded automatically.
	 *
	 * @var    boolean
	 * @since  1.0
	 */
	protected $autoloadLanguage = true;

	/**
	 * onAfterInitialise.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */

	protected $user;
	protected $eul_key;
	protected $session;

	public function __construct(&$subject, $config = array())
	{
		parent::__construct($subject, $config);
		$this->app = JFactory::getApplication();
		$this->session = JFactory::getSession();
		$this->eul_key = $this->params->get('eul_key');
	}

	public function onAfterInitialise()
	{
		$input  = $this->app->input;
		$userId = $input->getInt('uid', 0);
		$secret = $input->getString('xwsSK', 0);
		$isroot = false;

		// So we check if we have a user id and run if we do
		if ($userId) {
			// Great load the user
			$user   = JFactory::getUser($userId);

			// Check if the user is Root.
			$isroot = $user->authorise('core.admin');
		}

		// For security we will NOT allow super users to login with this method.
		if (!$isroot && $userId && $secret) {

			// Ok we passed all checks, lets marry up the data now:

			// Get a db connection.
			$db = JFactory::getDbo();

			// Create a new query object.
			$query = $db->getQuery(true);

			// Select all articles for users who have a username which starts with 'a'.
			// Order it by the created date.
			// Note by putting 'a' as a second parameter will generate `#__content` AS `a`
			$query
				->select('f.id, fv.value')
				->from($db->quoteName('#__fields', 'f'))
				->join('LEFT', $db->quoteName('#__fields_values', 'fv') . ' ON (' . $db->quoteName('f.id') . ' = ' . $db->quoteName('fv.field_id') . ')')
				->where($db->quoteName('f.name') . ' = ' . $db->quote('xws-autologin-secret-key'))
				->where($db->quoteName('fv.item_id') . ' = ' . $db->quote($userId));

			// Reset the query using our newly populated query object.
			$db->setQuery($query);

			// Load the results as a list of stdClass objects (see later for more options on retrieving data).
			$results = $db->loadObject();

			$authorisedGroup = false;
			$groupsCount = $this->params->get('userGroups');

			foreach ($this->params->get('userGroups') as $i => $group) {
				$authorisedGroup = in_array($group, $user->groups);
				if ($authorisedGroup) break;
			}

			// ONLY Log the user in if the Secret Key Matches
			if ($secret === $results->value && $authorisedGroup)
			{
				$url = substr(JURI::getInstance()->toString(), 0, strpos(JURI::getInstance()->toString(), 'uid='));
				$logMeIn = $this->loginUser($userId, $url);
			}
		}
	}

	/**
	 * onAfterRoute.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterRoute()
	{
	
	}

	/**
	 * onAfterDispatch.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterDispatch()
	{
	
	}

	/**
	 * onAfterRender.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterRender()
	{

	}

	/**
	 * onAfterCompileHead.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterCompileHead()
	{
	
	}

	/**
	 * OnAfterCompress.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterCompress()
	{
	
	}

	/**
	 * onAfterRespond.
	 *
	 * @return  void.
	 *
	 * @since   1.0
	 */
	public function onAfterRespond()
	{
	
	}

	/**
	 * Log in the selected user providing ID loads users and secret matches.
	 *
	 * @param $eul_id - Users ID
	 **
	 * @param $redirect - Where the user should be redirected too
	 *
	 * @return bool
	 *
	 * @since 1.0
	 */
	private function loginUser($eul_id, $redirect = 'index.php')
	{
		// Get this used based on their ID
		$this->user = JFactory::getUser($eul_id);

		if(!empty($this->user->id))
		{
			// If user is blocked, stop login.
			if(!empty($this->user->get('block', false)))
			{
				// Redirect with notice
				$this->app->enqueueMessage(JText::sprintf('PLG_XWS_AUTOLOGIN_BLOCKED', $this->user->username, $this->user->id), 'warning');
				$this->app->redirect($redirect);

				return false;
			}

			// Set the session
			$this->session->set('user', $this->user);

			$this->updateSessionTable();

			$this->user->setLastVisit();

			$this->app->enqueueMessage(JText::sprintf('PLG_XWS_AUTOLOGIN_SUCCESSFULL', $this->user->name), 'success');
			$this->app->redirect($redirect);
			return true;
		}

		$this->app->enqueueMessage(JText::_('PLG_XWS_AUTOLOGIN_ERROR_LOGIN'), 'error');
		$this->app->redirect($redirect);

		return false;
	}

	/**
	 * Function to update the Session Table in the database
	 *
	 * @since 1.0
	 */
	private function updateSessionTable()
	{

		// Get Session Table Instance
		$table = JTable::getInstance('session');

		// Load Session
		$table->load($this->session->getId());

		// Set the table username
		$table->username = $this->user->get('username');

		// Set the user id
		$table->userid = $this->user->get('id');

		// Make sure guest is set to No
		$table->guest = 0;

		// Update this users session with the above
		$table->update();
	}
}
