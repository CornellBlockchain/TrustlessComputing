pragma solidity ^0.4.24;


contract mainContract {
  event Request(address indexed requester, uint256 id, uint256 indexed bounty, uint256 prime);
  event Verification(address indexed solver, uint256 indexed id);
  event Success(uint256 indexed p,uint256 indexed q,uint256 indexed r);


  mapping (uint256 => uint256) bounties; // stores the bounty for solving each one
  mapping (uint256 => address) owners; // stores the person who requested each problem
  mapping (uint256 => uint256) problems; // stores the prime to factor associated with a problemid
  mapping (uint256 => uint256) problemToNonces;
  mapping (uint256 => bool) verifiedProblems;
  mapping (uint256 => address) rightfulOwner;

  uint256 nonce;
  uint256 threshold;
  address verifierContract;
  constructor(address v) {
    nonce = 0;
    threshold = 500 wei;
    verifierContract = v;
  }

  function requestComputing(uint256 bounty, uint256 problem) returns (uint256 Generatednonce){
    nonce++;
    if (bounty > threshold && msg.value >= bounty){
      bounties[nonce] = bounty;
      owners[nonce] = msg.sender;
      problems[nonce] = problem;
      problemToNonces[problem] = nonce;
      verifiedProblems[nonce] = false;
      emit Request(msg.sender, bounty, nonce, problem);
      return nonce;
    }else{
      assert(true);
    }
  }

  modifier verifierOnly(){
    require(msg.sender == verifierContract);
    _;

  }

  function receiveVerification(uint256 problem0, address sender) verifierOnly
    returns (bool success)
  {
    if(problem0 != 0){
      uint256 problemId = problemToNonces[problem0];
      verifiedProblems[problemId] = true;
      emit Verification(sender, problemId);
      rightfulOwner[problemId] = sender;
      return true;
    }
    return false;
  }


  function receiveProperFactoringAndPayout(uint256 p, uint256 q, uint256 r) returns (bool success){
      if (p*q == r && rightfulOwner[problemToNonces[p*q]] == msg.sender){
        uint256 problemId = problemToNonces[p*q];
        verifiedProblems[problemId] = true;
        emit Success(p,q,r);
        msg.sender.transfer(bounties[problemId]);
        return true;
      }else{
        return false;
      }
  }

  function cancelRequest(uint256 identifier) returns (bool success){
    if(msg.sender == owners[identifier]){
      delete bounties[identifier];
      delete owners[identifier];
      uint256 temp = problems[identifier];
      delete problems[identifier];
      delete problemToNonces[identifier];
      return true;
    }else{
      return false;
    }
  }

  function getProblem(uint256 identifier) returns (uint256 problem){
    return problems[identifier];
  }
  function getBounty(uint256 identifier) returns (uint256 bounty){
    return bounties[identifier];
  }
  function getOwner(uint256 identifier) returns (address owner){
    return owners[identifier];
  }


}
