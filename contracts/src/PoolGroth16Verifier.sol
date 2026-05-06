// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract PoolGroth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 17662636731906445441713532452823035302820960793116552139261854305035722638402;
    uint256 constant deltax2 = 9523993313529240934833338338506894541799246086808631220656966344382961090104;
    uint256 constant deltay1 = 14559284151572724262640398227909990848650550286114615571207209390139495389385;
    uint256 constant deltay2 = 18053580355189984402155768374859935564397876102508090259492025497042793506210;

    
    uint256 constant IC0x = 6251128491006576975464608998745730063203126257710012950147245613265083104078;
    uint256 constant IC0y = 4358594320216710973424080250967897587875556369072994083524613923329314206694;
    
    uint256 constant IC1x = 19328188513176886913976828290964719128176411488982685593885779353020606460526;
    uint256 constant IC1y = 4107899146187342297972259475991370771502577509952477322539207252979013327762;
    
    uint256 constant IC2x = 13730619270311694569938371707083289812398086127629069577340825046284527797574;
    uint256 constant IC2y = 8572779718837432883751868528077990552795622110693576842559080177633718737187;
    
    uint256 constant IC3x = 6343061745339434409606093311601410893585128568850343477711272022590910000903;
    uint256 constant IC3y = 6589710809040980768916620417654363309304642055505510081141113276445164636548;
    
    uint256 constant IC4x = 3166492715946167967525200768538800959651787215373962562744315471829128042364;
    uint256 constant IC4y = 11853123674280488227208490662754893290234648707473738862654512430695390324606;
    
    uint256 constant IC5x = 16748630884616646100860898023214017045384255769544291830897813459576670172145;
    uint256 constant IC5y = 9805167210824213819901390711885579533789854464588635656407913557526477882187;
    
    uint256 constant IC6x = 618387263339774868537601345046567983932190726076902450976536814069627880781;
    uint256 constant IC6y = 666212404167790121508958595648958057905790367468989379775247658076849769567;
    
    uint256 constant IC7x = 17204434840233577293982227246590544939400432789632553531642734013195466653007;
    uint256 constant IC7y = 12759735207140053586542109093649133621171128158303154710137307044436264069717;
    
    uint256 constant IC8x = 11622346812103938627615269523870720900182353613287981791359017450589444319891;
    uint256 constant IC8y = 6916781370311969492303016254834227100428892614760504029680464479352352652401;
    
    uint256 constant IC9x = 4502192700263165302026794990615550356808919733834794766231409251222532280369;
    uint256 constant IC9y = 17846391502892162479631381557309503802111020859167154898545738570017050091676;
    
    uint256 constant IC10x = 1530592568611302234315398746000235282627141911816405765595924556097906288341;
    uint256 constant IC10y = 20198956411346587099165504381159348250352204125966906341811917713630576432834;
    
    uint256 constant IC11x = 393233953531031432662965421493001791676114985233073427525855627091239158854;
    uint256 constant IC11y = 19142412975982979481471558158992987125079482831088011991582467922436197782948;
    
    uint256 constant IC12x = 4317491193328100605576720937370674378484829214426734790681159323682570015966;
    uint256 constant IC12y = 10482295921297911750198703129002055289695434147362610461496580007054469510785;
    
    uint256 constant IC13x = 9315781331377082214154830867130328639059242784581265771848929716621052857889;
    uint256 constant IC13y = 87928002193935386455466010433307979835922279444973985034062047297376302959;
    
    uint256 constant IC14x = 21878194293980388033716224755886467395852261210001106435711053831000090507954;
    uint256 constant IC14y = 2555386700132998486855030606028790602598449821014919876062369697446347462118;
    
    uint256 constant IC15x = 18383564137593513610662529364809059794660782879413895642616106865979173527135;
    uint256 constant IC15y = 393434458617162546477853605158897319222072134619020558125016778124604872157;
    
    uint256 constant IC16x = 13145060854550564056954944105328359762464011537323807387964245404668040181431;
    uint256 constant IC16y = 12706549075668107237844573151518406366369737180494360078909237856647006850294;
    
    uint256 constant IC17x = 13703662972121494171609529145352972817797239103374653719271454657441132251510;
    uint256 constant IC17y = 11068813137761919448010448844337653570309336953510946624660919946799894517432;
    
    uint256 constant IC18x = 20594225345418212567644306139285868141404765809519366005091275120238913143218;
    uint256 constant IC18y = 16866255810461421469334874219916041497028000401905374214830489806107447207908;
    
    uint256 constant IC19x = 3569743376317329572356339932599809221743221792690748427261166950873691920712;
    uint256 constant IC19y = 2274226713147987174034322651966937145554306987082066168326916376585315679592;
    
    uint256 constant IC20x = 14974694720520405300447163674970619458708178649358736208683958865913585748488;
    uint256 constant IC20y = 411607131780800019798862464673048323075934173802886189181732344253115359303;
    
    uint256 constant IC21x = 15059412159546867388928531887166873975229785465361350027562291625924388810013;
    uint256 constant IC21y = 16170946436207515607835983658575562173123499786864547058897590702819518005223;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[21] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
