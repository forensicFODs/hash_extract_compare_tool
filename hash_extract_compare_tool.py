#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
포렌식 해시 무결성 검증 도구
SHA256 해시를 이용한 파일 무결성 검증 및 베이스라인 비교
"""

import os
import hashlib
import sys
import json
from pathlib import Path
from datetime import datetime
import glob
import re


class ForensicHashTool:
    """포렌식 해시 도구 메인 클래스"""
    
    def __init__(self):
        self.baseline_pattern = "baseline_*.txt"
        self.results = []
        # 프로그램 실행 경로 기준 reports 폴더
        self.script_dir = Path(__file__).parent
        self.reports_dir = self.script_dir / "reports"
        
    def calculate_sha256(self, file_path):
        """파일의 SHA256 해시 계산"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def get_all_files(self, folder_path, recursive=True):
        """폴더 내 모든 파일 경로 가져오기"""
        file_list = []
        folder = Path(folder_path)
        
        if not folder.exists():
            print(f"❌ 오류: 폴더 '{folder_path}'가 존재하지 않습니다.")
            return file_list
        
        if not folder.is_dir():
            print(f"❌ 오류: '{folder_path}'는 폴더가 아닙니다.")
            return file_list
        
        if recursive:
            for item in folder.rglob('*'):
                if item.is_file() and not self._is_baseline_file(item):
                    file_list.append(item)
        else:
            for item in folder.glob('*'):
                if item.is_file() and not self._is_baseline_file(item):
                    file_list.append(item)
        
        return sorted(file_list)
    
    def _is_baseline_file(self, file_path):
        """베이스라인 파일인지 확인 (스캔에서 제외)"""
        name = file_path.name
        return name.startswith('baseline_') and name.endswith('.txt')
    
    def find_baselines(self, folder_path):
        """폴더에서 베이스라인 파일 자동 탐지"""
        folder = Path(folder_path)
        folder_name = folder.name if folder.name else 'root'
        baseline_files = []
        
        # reports 폴더에서 해당 폴더명의 베이스라인 검색
        report_folder = self.reports_dir / folder_name
        if report_folder.exists():
            pattern = report_folder / self.baseline_pattern
            found_files = glob.glob(str(pattern))
        else:
            found_files = []
        
        for filepath in found_files:
            try:
                metadata = self._read_baseline_metadata(filepath)
                baseline_files.append({
                    'path': filepath,
                    'metadata': metadata
                })
            except:
                # 메타데이터 읽기 실패 시 기본 정보만
                baseline_files.append({
                    'path': filepath,
                    'metadata': {
                        'created': datetime.fromtimestamp(os.path.getmtime(filepath)),
                        'target_folder': 'Unknown'
                    }
                })
        
        # 생성 시간 순 정렬 (최신 순)
        baseline_files.sort(key=lambda x: x['metadata'].get('created', datetime.min), reverse=True)
        
        return baseline_files
    
    def _read_baseline_metadata(self, filepath):
        """베이스라인 파일에서 메타데이터 읽기"""
        metadata = {}
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('# METADATA:'):
                    try:
                        json_str = line.replace('# METADATA:', '').strip()
                        metadata = json.loads(json_str)
                        # 문자열을 datetime으로 변환
                        if 'created' in metadata:
                            metadata['created'] = datetime.fromisoformat(metadata['created'])
                        break
                    except:
                        pass
        
        return metadata
    
    def create_baseline(self, folder_path, output_file=None, recursive=True):
        """베이스라인 생성"""
        folder = Path(folder_path)
        folder_name = folder.name if folder.name else 'root'
        
        # reports 폴더에 자동 저장
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_folder = self.reports_dir / folder_name
            report_folder.mkdir(parents=True, exist_ok=True)
            output_file = report_folder / f"baseline_{folder_name}_{timestamp}.txt"
        
        print(f"\n📸 베이스라인 생성 중...")
        print(f"대상 폴더: {folder_path}")
        print(f"하위 폴더 포함: {'예' if recursive else '아니오'}")
        print("-" * 80)
        
        files = self.get_all_files(folder_path, recursive)
        
        if not files:
            print("⚠ 처리할 파일이 없습니다.")
            return None
        
        print(f"총 {len(files)}개의 파일 발견\n")
        
        results = []
        base_path = Path(folder_path)
        total_size = 0
        
        for idx, file_path in enumerate(files, 1):
            relative_path = file_path.relative_to(base_path)
            print(f"[{idx}/{len(files)}] 처리 중: {relative_path}")
            
            file_size = file_path.stat().st_size
            total_size += file_size
            hash_value = self.calculate_sha256(file_path)
            
            results.append({
                'path': str(relative_path),
                'hash': hash_value,
                'size': file_size
            })
        
        # 메타데이터 생성
        metadata = {
            'created': datetime.now().isoformat(),
            'target_folder': str(folder_path),
            'file_count': len(results),
            'total_size': total_size,
            'recursive': recursive
        }
        
        # 베이스라인 파일 저장
        self._save_baseline(output_file, results, metadata)
        
        print(f"\n✅ 베이스라인이 생성되었습니다!")
        print(f"📁 저장 위치: {output_file}")
        print(f"📂 reports 폴더에 저장됨 (검사 대상 폴더와 분리)")
        print(f"📊 파일 수: {len(results)}개")
        print(f"💾 총 크기: {self._format_size(total_size)}")
        print(f"\n⚠ 이 파일을 안전하게 보관하세요!")
        
        return str(output_file)
    
    def _save_baseline(self, output_file, results, metadata):
        """베이스라인 파일 저장"""
        with open(output_file, 'w', encoding='utf-8') as f:
            # 메타데이터 저장 (JSON 형식)
            f.write(f"# METADATA: {json.dumps(metadata)}\n")
            f.write("=" * 80 + "\n")
            f.write("파일 SHA256 베이스라인\n")
            f.write(f"생성 시간: {metadata['created']}\n")
            f.write(f"대상 폴더: {metadata['target_folder']}\n")
            f.write(f"총 파일 수: {metadata['file_count']}\n")
            f.write(f"총 크기: {self._format_size(metadata['total_size'])}\n")
            f.write("=" * 80 + "\n\n")
            
            # 파일 정보 저장
            for result in results:
                f.write(f"파일명: {result['path']}\n")
                f.write(f"크기: {result['size']:,} bytes\n")
                f.write(f"SHA256: {result['hash']}\n")
                f.write("-" * 80 + "\n")
    
    def load_baseline(self, baseline_file):
        """베이스라인 파일 로드"""
        baseline_data = {}
        metadata = {}
        
        with open(baseline_file, 'r', encoding='utf-8') as f:
            current_file = {}
            
            for line in f:
                line = line.strip()
                
                # 메타데이터 파싱
                if line.startswith('# METADATA:'):
                    try:
                        json_str = line.replace('# METADATA:', '').strip()
                        metadata = json.loads(json_str)
                    except:
                        pass
                    continue
                
                if line.startswith('파일명: '):
                    if current_file:
                        baseline_data[current_file['path']] = current_file
                    current_file = {'path': line.replace('파일명: ', '')}
                
                elif line.startswith('크기: '):
                    size_str = line.replace('크기: ', '').replace(' bytes', '').replace(',', '')
                    current_file['size'] = int(size_str)
                
                elif line.startswith('SHA256: '):
                    current_file['hash'] = line.replace('SHA256: ', '')
            
            # 마지막 파일 추가
            if current_file:
                baseline_data[current_file['path']] = current_file
        
        return baseline_data, metadata
    
    def verify_integrity(self, folder_path, baseline_file, recursive=True):
        """베이스라인과 현재 상태 비교"""
        print(f"\n🔍 무결성 검증 중...")
        print(f"베이스라인: {baseline_file}")
        print(f"대상 폴더: {folder_path}")
        print("-" * 80)
        
        # 베이스라인 로드
        baseline_data, metadata = self.load_baseline(baseline_file)
        print(f"✓ 베이스라인 로드 완료 ({len(baseline_data)}개 파일)")
        
        # 현재 상태 스캔
        print(f"\n현재 상태 스캔 중...\n")
        files = self.get_all_files(folder_path, recursive)
        
        current_data = {}
        base_path = Path(folder_path)
        
        for idx, file_path in enumerate(files, 1):
            relative_path = str(file_path.relative_to(base_path))
            print(f"[{idx}/{len(files)}] 검사 중: {relative_path}")
            
            file_size = file_path.stat().st_size
            hash_value = self.calculate_sha256(file_path)
            
            current_data[relative_path] = {
                'path': relative_path,
                'hash': hash_value,
                'size': file_size
            }
        
        # 비교 분석
        print(f"\n분석 중...\n")
        report = self._compare_states(baseline_data, current_data)
        
        # 리포트 출력
        self._print_report(report, metadata)
        
        # 리포트 파일 저장
        report_file = self._save_report(report, metadata, folder_path)
        
        return report, report_file
    
    def _compare_states(self, baseline, current):
        """베이스라인과 현재 상태 비교"""
        report = {
            'unchanged': [],
            'modified': [],
            'deleted': [],
            'new': []
        }
        
        baseline_paths = set(baseline.keys())
        current_paths = set(current.keys())
        
        # 변경 없음 & 변조된 파일
        for path in baseline_paths & current_paths:
            if baseline[path]['hash'] == current[path]['hash']:
                report['unchanged'].append({
                    'path': path,
                    'hash': baseline[path]['hash']
                })
            else:
                report['modified'].append({
                    'path': path,
                    'old_hash': baseline[path]['hash'],
                    'new_hash': current[path]['hash'],
                    'old_size': baseline[path]['size'],
                    'new_size': current[path]['size']
                })
        
        # 삭제된 파일
        for path in baseline_paths - current_paths:
            report['deleted'].append({
                'path': path,
                'hash': baseline[path]['hash']
            })
        
        # 새로 추가된 파일
        for path in current_paths - baseline_paths:
            report['new'].append({
                'path': path,
                'hash': current[path]['hash'],
                'size': current[path]['size']
            })
        
        return report
    
    def _print_report(self, report, metadata):
        """검증 리포트 출력"""
        print("\n" + "=" * 80)
        print("🔐 무결성 검증 리포트")
        print("=" * 80)
        
        if metadata:
            baseline_time = metadata.get('created', 'Unknown')
            print(f"베이스라인 생성: {baseline_time}")
        print(f"검증 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        total = len(report['unchanged']) + len(report['modified']) + len(report['deleted']) + len(report['new'])
        
        print(f"\n📊 요약:")
        print(f"  총 파일 수: {total}개")
        print(f"  ✅ 변경 없음: {len(report['unchanged'])}개")
        print(f"  ⚠️  변조됨: {len(report['modified'])}개")
        print(f"  ❌ 삭제됨: {len(report['deleted'])}개")
        print(f"  🆕 추가됨: {len(report['new'])}개")
        
        # 변조된 파일 상세
        if report['modified']:
            print(f"\n⚠️  변조된 파일 ({len(report['modified'])}개):")
            print("-" * 80)
            for item in report['modified']:
                print(f"  📄 {item['path']}")
                print(f"     이전 해시: {item['old_hash'][:16]}...")
                print(f"     현재 해시: {item['new_hash'][:16]}...")
                print(f"     크기 변화: {item['old_size']:,} → {item['new_size']:,} bytes")
                print()
        
        # 삭제된 파일
        if report['deleted']:
            print(f"\n❌ 삭제된 파일 ({len(report['deleted'])}개):")
            print("-" * 80)
            for item in report['deleted']:
                print(f"  📄 {item['path']}")
            print()
        
        # 새로 추가된 파일
        if report['new']:
            print(f"\n🆕 추가된 파일 ({len(report['new'])}개):")
            print("-" * 80)
            for item in report['new']:
                print(f"  📄 {item['path']}")
                print(f"     해시: {item['hash'][:16]}...")
                print(f"     크기: {item['size']:,} bytes")
            print()
        
        # 결론
        print("=" * 80)
        if not report['modified'] and not report['deleted'] and not report['new']:
            print("✅ 무결성 검증 통과: 모든 파일이 베이스라인과 일치합니다!")
        else:
            print("⚠️  무결성 검증 실패: 변경 사항이 발견되었습니다!")
        print("=" * 80)
    
    def _save_report(self, report, metadata, folder_path):
        """검증 리포트를 파일로 저장"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        folder = Path(folder_path)
        folder_name = folder.name if folder.name else 'root'
        
        # reports 폴더에 저장
        report_folder = self.reports_dir / folder_name
        report_folder.mkdir(parents=True, exist_ok=True)
        report_file = report_folder / f"integrity_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("무결성 검증 리포트\n")
            f.write("=" * 80 + "\n")
            
            if metadata:
                f.write(f"베이스라인 생성: {metadata.get('created', 'Unknown')}\n")
            f.write(f"검증 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"대상 폴더: {folder_path}\n")
            f.write("=" * 80 + "\n\n")
            
            # 요약
            total = len(report['unchanged']) + len(report['modified']) + len(report['deleted']) + len(report['new'])
            f.write(f"요약:\n")
            f.write(f"총 파일 수: {total}개\n")
            f.write(f"변경 없음: {len(report['unchanged'])}개\n")
            f.write(f"변조됨: {len(report['modified'])}개\n")
            f.write(f"삭제됨: {len(report['deleted'])}개\n")
            f.write(f"추가됨: {len(report['new'])}개\n\n")
            
            # 상세 내역
            if report['modified']:
                f.write("=" * 80 + "\n")
                f.write("변조된 파일:\n")
                f.write("=" * 80 + "\n")
                for item in report['modified']:
                    f.write(f"파일명: {item['path']}\n")
                    f.write(f"이전 해시: {item['old_hash']}\n")
                    f.write(f"현재 해시: {item['new_hash']}\n")
                    f.write(f"크기 변화: {item['old_size']:,} → {item['new_size']:,} bytes\n")
                    f.write("-" * 80 + "\n")
            
            if report['deleted']:
                f.write("\n" + "=" * 80 + "\n")
                f.write("삭제된 파일:\n")
                f.write("=" * 80 + "\n")
                for item in report['deleted']:
                    f.write(f"파일명: {item['path']}\n")
                    f.write(f"해시: {item['hash']}\n")
                    f.write("-" * 80 + "\n")
            
            if report['new']:
                f.write("\n" + "=" * 80 + "\n")
                f.write("추가된 파일:\n")
                f.write("=" * 80 + "\n")
                for item in report['new']:
                    f.write(f"파일명: {item['path']}\n")
                    f.write(f"해시: {item['hash']}\n")
                    f.write(f"크기: {item['size']:,} bytes\n")
                    f.write("-" * 80 + "\n")
        
        print(f"\n📄 리포트 저장됨: {report_file}")
        return str(report_file)
    
    def _format_size(self, size):
        """파일 크기를 읽기 쉬운 형식으로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def interactive_mode(self):
        """대화형 모드"""
        print("=" * 80)
        print("🔐 포렌식 해시 무결성 검증 도구")
        print("=" * 80)
        print()
        
        # 폴더 경로 입력
        folder_path = input("검사할 폴더 경로를 입력하세요: ").strip()
        
        if not folder_path:
            print("❌ 폴더 경로가 입력되지 않았습니다.")
            return
        
        if not os.path.exists(folder_path):
            print(f"❌ 폴더 '{folder_path}'가 존재하지 않습니다.")
            return
        
        # 베이스라인 자동 탐지
        print(f"\n🔍 베이스라인 자동 탐지 중...")
        baselines = self.find_baselines(folder_path)
        
        if baselines:
            print(f"\n✓ {len(baselines)}개의 베이스라인을 발견했습니다:\n")
            
            for idx, bl in enumerate(baselines, 1):
                meta = bl['metadata']
                created = meta.get('created', 'Unknown')
                target = meta.get('target_folder', 'Unknown')
                file_count = meta.get('file_count', '?')
                
                # 시간 차이 계산
                if isinstance(created, datetime):
                    time_diff = datetime.now() - created
                    if time_diff.days > 0:
                        time_str = f"{time_diff.days}일 전"
                    elif time_diff.seconds > 3600:
                        time_str = f"{time_diff.seconds // 3600}시간 전"
                    else:
                        time_str = f"{time_diff.seconds // 60}분 전"
                    created_str = f"{created.strftime('%Y-%m-%d %H:%M:%S')} ({time_str})"
                else:
                    created_str = str(created)
                
                # 대상 폴더 일치 여부
                match_icon = "✓" if str(target) == str(folder_path) else "⚠"
                latest_icon = "⭐ 최신" if idx == 1 else ""
                
                print(f"{idx}) {Path(bl['path']).name}")
                print(f"   생성: {created_str} {latest_icon}")
                print(f"   대상: {target} {match_icon}")
                print(f"   파일: {file_count}개")
                print()
            
            print("다음 중 선택하세요:")
            print("1) 베이스라인과 비교 (무결성 검증)")
            print("2) 새 베이스라인 생성")
            print("3) 다른 베이스라인 파일 지정")
            print("4) 베이스라인 없이 해시만 추출")
            print()
            
            choice = input("선택 [1]: ").strip() or "1"
            
            if choice == "1":
                # 어느 베이스라인 사용할지
                if len(baselines) > 1:
                    bl_choice = input(f"\n어느 베이스라인을 사용하시겠습니까? [1]: ").strip() or "1"
                    try:
                        bl_idx = int(bl_choice) - 1
                        if 0 <= bl_idx < len(baselines):
                            baseline_file = baselines[bl_idx]['path']
                        else:
                            baseline_file = baselines[0]['path']
                    except:
                        baseline_file = baselines[0]['path']
                else:
                    baseline_file = baselines[0]['path']
                
                # 무결성 검증 실행
                self.verify_integrity(folder_path, baseline_file)
                
            elif choice == "2":
                self.create_baseline(folder_path)
                
            elif choice == "3":
                custom_baseline = input("베이스라인 파일 경로: ").strip()
                if os.path.exists(custom_baseline):
                    self.verify_integrity(folder_path, custom_baseline)
                else:
                    print(f"❌ 파일 '{custom_baseline}'을 찾을 수 없습니다.")
                    
            elif choice == "4":
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                folder = Path(folder_path)
                folder_name = folder.name if folder.name else 'root'
                report_folder = self.reports_dir / folder_name
                report_folder.mkdir(parents=True, exist_ok=True)
                output = report_folder / f"hashes_{timestamp}.txt"
                self.create_baseline(folder_path, output)
        
        else:
            # 베이스라인이 없는 경우
            print("✗ 베이스라인을 발견하지 못했습니다.\n")
            print("이 도구를 처음 사용하시나요?")
            print("→ 먼저 '베이스라인'을 생성해야 합니다.")
            print("→ 베이스라인은 원본 상태를 기록하는 파일입니다.\n")
            
            print("다음 중 선택하세요:")
            print("1) 베이스라인 생성 (최초 해시 기록)")
            print("2) 기존 베이스라인 파일 지정")
            print("3) 베이스라인 없이 해시만 추출")
            print()
            
            choice = input("선택 [1]: ").strip() or "1"
            
            if choice == "1":
                self.create_baseline(folder_path)
                
            elif choice == "2":
                custom_baseline = input("베이스라인 파일 경로: ").strip()
                if os.path.exists(custom_baseline):
                    self.verify_integrity(folder_path, custom_baseline)
                else:
                    print(f"❌ 파일 '{custom_baseline}'을 찾을 수 없습니다.")
                    
            elif choice == "3":
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                folder = Path(folder_path)
                folder_name = folder.name if folder.name else 'root'
                report_folder = self.reports_dir / folder_name
                report_folder.mkdir(parents=True, exist_ok=True)
                output = report_folder / f"hashes_{timestamp}.txt"
                self.create_baseline(folder_path, output)


def main():
    """메인 함수"""
    tool = ForensicHashTool()
    
    # 명령줄 인자 처리
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("""
포렌식 해시 무결성 검증 도구 사용법:

1. 대화형 모드 (추천):
   python forensic_hash_tool.py

2. 베이스라인 생성:
   python forensic_hash_tool.py --create <폴더경로>

3. 무결성 검증:
   python forensic_hash_tool.py --verify <폴더경로> --baseline <베이스라인파일>

4. 자동 검증 (베이스라인 자동 탐지):
   python forensic_hash_tool.py --auto <폴더경로>
            """)
            return
        
        elif sys.argv[1] == '--create':
            if len(sys.argv) > 2:
                tool.create_baseline(sys.argv[2])
            else:
                print("❌ 폴더 경로를 지정해주세요.")
        
        elif sys.argv[1] == '--verify':
            if len(sys.argv) > 3 and sys.argv[3] == '--baseline':
                if len(sys.argv) > 4:
                    tool.verify_integrity(sys.argv[2], sys.argv[4])
                else:
                    print("❌ 베이스라인 파일을 지정해주세요.")
            else:
                print("❌ 사용법: --verify <폴더> --baseline <베이스라인파일>")
        
        elif sys.argv[1] == '--auto':
            if len(sys.argv) > 2:
                folder = sys.argv[2]
                baselines = tool.find_baselines(folder)
                if baselines:
                    tool.verify_integrity(folder, baselines[0]['path'])
                else:
                    print("❌ 베이스라인을 찾을 수 없습니다. 먼저 생성해주세요.")
            else:
                print("❌ 폴더 경로를 지정해주세요.")
        
        else:
            # 폴더 경로만 입력된 경우 - 대화형 모드로 전환
            tool.interactive_mode()
    else:
        # 인자 없이 실행 - 대화형 모드
        tool.interactive_mode()


if __name__ == "__main__":
    main()
