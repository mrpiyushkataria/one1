<?php
// includes/graph_builder.php
require_once __DIR__ . '/../config.php';

function rebuild_graph_cache(int $project_id): array {
  $conn = db();

  $nodes=[]; $links=[];
  $asset_ids=[];

  $stmt = $conn->prepare("SELECT id, asset_type, asset_value, meta_json FROM oneinseclabs_assets WHERE project_id=?");
  $stmt->bind_param("i", $project_id);
  $stmt->execute();
  $res = $stmt->get_result();

  while ($row = $res->fetch_assoc()) {
    $id=(int)$row['id'];
    $asset_ids[$id]=true;
    $nodes[]=[
      'id'=>"a:$id",
      'type'=>$row['asset_type'],
      'label'=>$row['asset_value'],
      'meta'=>$row['meta_json'] ? json_decode($row['meta_json'], true) : null
    ];
  }

  $stmt2 = $conn->prepare("SELECT from_asset_id, to_asset_id, link_type FROM oneinseclabs_asset_links WHERE project_id=?");
  $stmt2->bind_param("i",$project_id);
  $stmt2->execute();
  $res2=$stmt2->get_result();
  while($r=$res2->fetch_assoc()){
    $from=(int)$r['from_asset_id']; $to=(int)$r['to_asset_id'];
    if(!isset($asset_ids[$from],$asset_ids[$to])) continue;
    $links[]=['source'=>"a:$from",'target'=>"a:$to",'type'=>$r['link_type']];
  }

  // Port nodes derived
  $stmt3 = $conn->prepare("SELECT ip_asset_id, port, protocol, state, service_name, product, version FROM oneinseclabs_ports WHERE project_id=?");
  $stmt3->bind_param("i",$project_id);
  $stmt3->execute();
  $res3=$stmt3->get_result();
  while($p=$res3->fetch_assoc()){
    $ip_id=(int)$p['ip_asset_id'];
    if(!isset($asset_ids[$ip_id])) continue;

    $portNodeId="p:$ip_id:".$p['protocol'].":".$p['port'];
    $label=$p['protocol']."/".$p['port']." • ".($p['service_name'] ?: 'service')
        .($p['product'] ? " • ".$p['product'] : '')
        .($p['version'] ? " ".$p['version'] : '');

    $nodes[]=[
      'id'=>$portNodeId,
      'type'=>'port',
      'label'=>$label,
      'meta'=>[
        'state'=>$p['state'],
        'service'=>$p['service_name'],
        'product'=>$p['product'],
        'version'=>$p['version']
      ]
    ];
    $links[]=['source'=>"a:$ip_id",'target'=>$portNodeId,'type'=>'has_port'];
  }

  $graph=['nodes'=>$nodes,'links'=>$links];
  $graph_json=json_encode($graph, JSON_UNESCAPED_UNICODE);

  $stmt4=$conn->prepare("
    INSERT INTO oneinseclabs_graph_cache (project_id, graph_json, updated_at)
    VALUES (?, ?, NOW())
    ON DUPLICATE KEY UPDATE graph_json=VALUES(graph_json), updated_at=NOW()
  ");
  $stmt4->bind_param("is",$project_id,$graph_json);
  $stmt4->execute();

  return ['ok'=>true,'nodes'=>count($nodes),'links'=>count($links)];
}
