component extends="base" {
    /**
    * Returns PLAIN response
    *
    * @param string authcid Authentication id (username)
    * @param string pass Password
    * @param string authzid Autorization id
    * @return string PLAIN Response
    **/
    public function getResponse(authcid, pass, authzid = '')
    {
        return authzid & chr(0) & authcid & chr(0) & pass;
    }
}