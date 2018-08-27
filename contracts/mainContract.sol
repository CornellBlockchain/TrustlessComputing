pragma solidity ^0.4.24;


contract mainContract {
  event Request(address indexed requester, uint256 indexed bounty, uint256 prime);
  event Verification(address indexed solver);
  event Succerss(uint256 indexed p,uint256 indexed q,uint256 indexed r);


  mapping (bytes32 => uint256) bounties; // stores the bounty for solving each one
  mapping (bytes32 => address) owners; // stores the person who requested each problem
  mapping (bytes32 => uint256) problems; // stores the prime to factor associated with a problemid
  mapping (uint256 => bytes32) problemToNonces;
  mapping (bytes32 => bool) verifiedProblems;
  mapping (bytes32 => address) rightfulOwner;

  uint256 nonce;

  constructor() {
    nonce = 0;
  }

  function requestComputing(uint256 bounty, bytes32 identifier, bytes problem) returns (bool success){
    nonce++;
    if (bounty > threshold){
      //initialize stuff
    }else{
      throw;
    }
  }

  modifier verifierOnly(){
    require(msg.sender == verifierContract)
    _;

  }

  function receiveVerification(uint256 problem0, uint256 problem1, address sender) returns (bool success)
    verifierOnly()
  {
    if(problem != 0){
      problemId = problemToNonces[problem0];
      verifiedProblems[problemId] = true
      Verification(sender);
      rightfulOwner[problemId] = sender;
      //some other stuff i think
    }
  }


  function receiveProperFactoringAndPayout(uint256 p, uint256 q, uint256 r) returns (bool success){
      if (p*q == r){
        Success(p,q,r);
        //payout
      }else{
        return false;
      }
  }

  function cancelRequest(bytes32 identifier) returns success{
    if(msg.sender == owners[identifier]){
      delete bounties[identifier];
      delete owners[identifier];
      uint256 temp = problems[identifier];
      delete problems[identifier];
      delete problemsToNonces[identifier];
      return true;
    }else{
      return false;
    }
  }

  function getProblem(bytes32 identifier){
    return problems[identifier]
  }
  function getBounty(bytes32 identifier){
    return bounties[identifier]
  }
  function getOwner(bytes32 identifier){
    return owners[identifier]
  }


}
