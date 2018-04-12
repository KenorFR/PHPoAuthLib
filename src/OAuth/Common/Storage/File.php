<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Storage\Exception\StorageException;
use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;

/**
 * Stores a token in a PHP session.
 */
class File implements TokenStorageInterface
{
    /**
     * @var string
     */
    protected $stateVariableName;
    
    /**
     * File path temp
     * 
     * @var string
     */
    protected $filePath;

    /**
     * Save data
     * 
     * @var array
     */
    protected $fileContentSave;

    public function __construct($filePath, $stateVariableName = 'uniq') {
        if (!file_exists($filePath)) {
            throw new StorageException('File not found');
        }
        
        $this->filePath = $filePath;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if ($this->hasAccessToken($service)) {
            $data = $this->getDataState();
            return unserialize($data[$service]);
        }

        throw new TokenNotFoundException('Token not store in file temp');
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        $serializedToken = serialize($token);
        
        $this->addDataState($service, $serializedToken);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        $data = $this->getDataState();
        
        return isset($data[$service]);
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        $this->removeDataState($service);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        $this->removeDataAll();

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        $this->addDataState($service, $state);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        $data = $this->getDataState();
        return isset($data[$service]);
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAuthorizationState($service)
    {
        if ($this->hasAuthorizationState($service)) {
            $data = $this->getDataState();
            return $data[$service];
        }

        throw new AuthorizationStateNotFoundException('State not found in session, are you sure you stored it?');
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        $data = $this->getDataState();
        if (array_key_exists($service, $data)) {
            $this->removeDataState($service);
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        unset($_SESSION[$this->stateVariableName]);
        $this->removeDataState();

        // allow chaining
        return $this;
    }

    /**
     * @return array
     */
    protected function getDataAll()
    {
        if ($this->fileContentSave !== null) {
            return $this->fileContentSave;
        }
        
        $dataJson = file_get_contents($this->filePath);

        $dataArray = json_decode($dataJson, true);

        if (!is_array($dataArray)) {
            return [];
        }

        return $dataArray;
    }

    /**
     * @return array
     */
    protected function getDataState()
    {
        $dataAll = $this->getDataAll();

        if (!isset($dataAll[$this->stateVariableName]) || !is_array($dataAll[$this->stateVariableName])) {
            $dataAll[$this->stateVariableName] = [];
        }
        
        return $dataAll[$this->stateVariableName];
    }
    
    protected function addDataState($key, $value)
    {
        $dataAll = $this->getDataAll();

        if (!isset($dataAll[$this->stateVariableName]) || !is_array($dataAll[$this->stateVariableName])) {
            $dataAll[$this->stateVariableName] = [];
        }

        $dataAll[$this->stateVariableName][$key] = $value;
        
        $this->saveDataAll($dataAll);
    }

    protected function removeDataState($key = true)
    {
        $dataAll = $this->getDataAll();

        if (!isset($dataAll[$this->stateVariableName]) || !is_array($dataAll[$this->stateVariableName])) {
            $dataAll[$this->stateVariableName] = [];
        }

        if ($key === true) {
            unset($dataAll[$this->stateVariableName]);
        } else {
            unset($dataAll[$key]);
        }

        $this->saveDataAll($dataAll);
    }

    protected function removeDataAll()
    {
        $this->saveDataAll([]);
    }
    
    protected function saveDataAll($datas)
    {
        $this->fileContentSave = $datas;
        file_put_contents($this->filePath, json_encode($datas));
    }

    protected function is_serialized($data, $strict = true)
    {
        // if it isn't a string, it isn't serialized.
        if (!is_string($data)) {
            return false;
        }
        $data = trim($data);
        if ('N;' == $data) {
            return true;
        }
        if (strlen($data) < 4) {
            return false;
        }
        if (':' !== $data[1]) {
            return false;
        }
        if ($strict) {
            $lastc = substr($data, -1);
            if (';' !== $lastc && '}' !== $lastc) {
                return false;
            }
        } else {
            $semicolon = strpos($data, ';');
            $brace = strpos($data, '}');
            // Either ; or } must exist.
            if (false === $semicolon && false === $brace)
                return false;
            // But neither must be in the first X characters.
            if (false !== $semicolon && $semicolon < 3)
                return false;
            if (false !== $brace && $brace < 4)
                return false;
        }
        $token = $data[0];
        switch ($token) {
            case 's' :
                if ($strict) {
                    if ('"' !== substr($data, -2, 1)) {
                        return false;
                    }
                } elseif (false === strpos($data, '"')) {
                    return false;
                }
            // or else fall through
            case 'a' :
            case 'O' :
                return (bool)preg_match("/^{$token}:[0-9]+:/s", $data);
            case 'b' :
            case 'i' :
            case 'd' :
                $end = $strict ? '$' : '';
                return (bool)preg_match("/^{$token}:[0-9.E-]+;$end/", $data);
        }
        return false;
    }
}
